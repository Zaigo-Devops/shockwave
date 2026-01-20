"""
Django management command to create mobile team members with active subscriptions.

Usage:
    python manage.py create_mobile_team_member email1@example.com email2@example.com
    python manage.py create_mobile_team_member email@example.com --password=SecurePass123
    python manage.py create_mobile_team_member email@example.com --days=365
"""
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone

from sw_admin_app.models import UserProfile, Subscription, SubscriptionPeriod
from sw_api_app.utils import get_attachment_from_name, ACTIVE


class Command(BaseCommand):
    help = 'Create mobile team members with active subscriptions for testing'

    def add_arguments(self, parser):
        parser.add_argument(
            'emails',
            nargs='+',
            type=str,
            help='Email addresses for the mobile team members'
        )
        parser.add_argument(
            '--password',
            type=str,
            default='MobileTeam@2026',
            help='Password for the new accounts (default: MobileTeam@2026)'
        )
        parser.add_argument(
            '--days',
            type=int,
            default=365,
            help='Number of days for subscription validity (default: 365)'
        )
        parser.add_argument(
            '--first-name',
            type=str,
            default='Mobile',
            help='First name for the user (default: Mobile)'
        )
        parser.add_argument(
            '--last-name',
            type=str,
            default='Tester',
            help='Last name for the user (default: Tester)'
        )
        parser.add_argument(
            '--address',
            type=str,
            default=None,
            help='Optional address for the user profile'
        )

    def handle(self, *args, **options):
        emails = options['emails']
        password = options['password']
        validity_days = options['days']
        first_name = options['first_name']
        last_name = options['last_name']
        address = options['address']

        for email in emails:
            self.stdout.write(f"\n{'='*50}")
            self.stdout.write(f"Processing: {email}")
            self.stdout.write('='*50)

            try:
                # Check if user already exists
                user, user_created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        'username': email,
                        'first_name': first_name,
                        'last_name': last_name,
                    }
                )

                if user_created:
                    user.set_password(password)
                    user.save()
                    self.stdout.write(self.style.SUCCESS(f"✓ Created User: {email}"))
                else:
                    self.stdout.write(self.style.WARNING(f"⚠ User already exists: {email}"))

                # Create or update UserProfile
                user_name = f"{first_name} {last_name}"
                profile, profile_created = UserProfile.objects.get_or_create(
                    user_id=user,
                    defaults={
                        'insurance_provider': None,
                        'is_promotion_email': True,
                        'user_profile_image': get_attachment_from_name(user_name),
                        'stripe_customer_id': f"dev_mobile_{user.pk}",  # Dev/test customer ID
                        'user_address': address,  # Optional address for test accounts
                    }
                )

                if profile_created:
                    self.stdout.write(self.style.SUCCESS(f"✓ Created UserProfile"))
                else:
                    # Update stripe_customer_id if missing
                    if not profile.stripe_customer_id:
                        profile.stripe_customer_id = f"dev_mobile_{user.pk}"
                        profile.save()
                    self.stdout.write(self.style.WARNING(f"⚠ UserProfile already exists"))

                # Check for existing active subscription
                existing_subscription = Subscription.objects.filter(
                    user_id=user,
                    status=ACTIVE,
                    app_subscribed=True
                ).first()

                if existing_subscription:
                    self.stdout.write(self.style.WARNING(
                        f"⚠ Active subscription already exists (ends: {existing_subscription.end_date})"
                    ))
                    # Optionally extend the subscription
                    if existing_subscription.end_date and existing_subscription.end_date < timezone.now():
                        existing_subscription.start_date = timezone.now()
                        existing_subscription.end_date = timezone.now() + timedelta(days=validity_days)
                        existing_subscription.save()
                        self.stdout.write(self.style.SUCCESS(
                            f"✓ Extended expired subscription to: {existing_subscription.end_date}"
                        ))
                else:
                    # Create new subscription
                    start_date = timezone.now()
                    end_date = start_date + timedelta(days=validity_days)

                    subscription = Subscription.objects.create(
                        status=ACTIVE,
                        app_subscribed=True,
                        user_id=user,
                        stripe_customer_id=f"dev_mobile_{user.pk}",
                        stripe_subscription_id=f"dev_sub_{user.pk}_{timezone.now().strftime('%Y%m%d')}",
                        subscription_price=0.0,  # Test subscription - no charge
                        start_date=start_date,
                        end_date=end_date,
                    )
                    self.stdout.write(self.style.SUCCESS(
                        f"✓ Created Subscription (Active until: {end_date.strftime('%Y-%m-%d')})"
                    ))

                    # Create SubscriptionPeriod
                    SubscriptionPeriod.objects.create(
                        subscription_id=subscription,
                        stripe_subscription_id=subscription.stripe_subscription_id,
                        stripe_customer_id=subscription.stripe_customer_id,
                        start_date=start_date,
                        end_date=end_date,
                    )
                    self.stdout.write(self.style.SUCCESS(f"✓ Created SubscriptionPeriod"))

                # Summary for this user
                self.stdout.write(self.style.SUCCESS(f"\n✅ {email} is ready for mobile testing!"))
                if user_created:
                    self.stdout.write(f"   Password: {password}")

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"✗ Error processing {email}: {str(e)}"))

        self.stdout.write(f"\n{'='*50}")
        self.stdout.write(self.style.SUCCESS("Done processing all emails!"))
        self.stdout.write('='*50)
