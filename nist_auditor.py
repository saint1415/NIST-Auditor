"""
NIST 800-63-4 Compliance Audit Tool - Enhanced with Data Capture
Audits authentication systems against NIST Special Publication 800-63-4
"""

import json
import re
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class AAL(Enum):
    """Authentication Assurance Levels"""
    AAL1 = 1
    AAL2 = 2
    AAL3 = 3


class IAL(Enum):
    """Identity Assurance Levels"""
    IAL1 = 1
    IAL2 = 2
    IAL3 = 3


class FAL(Enum):
    """Federation Assurance Levels"""
    FAL1 = 1
    FAL2 = 2
    FAL3 = 3


@dataclass
class AuditResult:
    """Result of a single audit check"""
    check_id: str
    category: str
    requirement: str
    status: str  # PASS, FAIL, WARNING, NOT_APPLICABLE
    details: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    remediation: str


class ConfigurationCollector:
    """Interactive collector for system configuration"""
    
    def __init__(self, interactive: bool = True):
        self.interactive = interactive
        self.config = {}
    
    def _prompt(self, question: str, options: List[str] = None, default: Any = None) -> str:
        """Prompt user for input"""
        if not self.interactive:
            return default
        
        if options:
            print(f"\n{question}")
            for i, option in enumerate(options, 1):
                print(f"  {i}. {option}")
            while True:
                try:
                    choice = input(f"Select (1-{len(options)}): ").strip()
                    idx = int(choice) - 1
                    if 0 <= idx < len(options):
                        return options[idx]
                    print(f"Please enter a number between 1 and {len(options)}")
                except (ValueError, KeyboardInterrupt):
                    if default:
                        return default
                    print("Invalid input. Please try again.")
        else:
            prompt_text = f"\n{question}"
            if default is not None:
                prompt_text += f" [{default}]"
            prompt_text += ": "
            
            response = input(prompt_text).strip()
            return response if response else default
    
    def _yes_no(self, question: str, default: bool = None) -> bool:
        """Ask yes/no question"""
        if not self.interactive:
            return default if default is not None else False
        
        default_str = " [Y/n]" if default else " [y/N]" if default is False else " [y/n]"
        response = input(f"\n{question}{default_str}: ").strip().lower()
        
        if not response:
            return default if default is not None else False
        
        return response in ['y', 'yes', 'true', '1']
    
    def collect_password_policy(self) -> Dict:
        """Collect password policy configuration"""
        print("\n" + "="*70)
        print("PASSWORD POLICY CONFIGURATION")
        print("="*70)
        
        policy = {}
        
        # Minimum length
        min_length = self._prompt(
            "What is the minimum password length required?",
            default="8"
        )
        policy['min_length'] = int(min_length) if min_length.isdigit() else 8
        
        # Maximum length
        max_length = self._prompt(
            "What is the maximum password length allowed?",
            default="128"
        )
        policy['max_length'] = int(max_length) if max_length.isdigit() else 128
        
        # Complexity requirements
        policy['requires_complexity'] = self._yes_no(
            "Do you enforce complexity rules (special chars, uppercase, numbers)?",
            default=False
        )
        
        if policy['requires_complexity']:
            policy['complexity_details'] = self._prompt(
                "Describe the complexity requirements",
                default="N/A"
            )
        
        # Breach checking
        policy['checks_breached_passwords'] = self._yes_no(
            "Do you check passwords against breach databases (e.g., Have I Been Pwned)?",
            default=False
        )
        
        if policy['checks_breached_passwords']:
            policy['breach_check_service'] = self._prompt(
                "Which service do you use for breach checking?",
                default="Have I Been Pwned"
            )
        
        # Password expiration
        has_expiration = self._yes_no(
            "Do passwords expire after a certain period?",
            default=False
        )
        
        if has_expiration:
            expiration_days = self._prompt(
                "How many days until passwords expire?",
                default="90"
            )
            policy['password_expiration_days'] = int(expiration_days) if expiration_days.isdigit() else 90
        else:
            policy['password_expiration_days'] = 0
        
        # Rate limiting
        policy['rate_limiting_enabled'] = self._yes_no(
            "Is rate limiting enabled for login attempts?",
            default=False
        )
        
        if policy['rate_limiting_enabled']:
            max_attempts = self._prompt(
                "How many failed attempts before lockout?",
                default="5"
            )
            policy['max_failed_attempts'] = int(max_attempts) if max_attempts.isdigit() else 5
            
            lockout_duration = self._prompt(
                "Lockout duration in minutes?",
                default="15"
            )
            policy['lockout_duration_minutes'] = int(lockout_duration) if lockout_duration.isdigit() else 15
        
        # Password history
        policy['prevents_password_reuse'] = self._yes_no(
            "Do you prevent password reuse?",
            default=False
        )
        
        if policy['prevents_password_reuse']:
            history_count = self._prompt(
                "How many previous passwords are remembered?",
                default="5"
            )
            policy['password_history_count'] = int(history_count) if history_count.isdigit() else 5
        
        return policy
    
    def collect_mfa_config(self) -> Dict:
        """Collect MFA configuration"""
        print("\n" + "="*70)
        print("MULTI-FACTOR AUTHENTICATION CONFIGURATION")
        print("="*70)
        
        mfa = {}
        
        mfa['enabled'] = self._yes_no(
            "Is multi-factor authentication (MFA) enabled?",
            default=False
        )
        
        if mfa['enabled']:
            mfa['required_for_all_users'] = self._yes_no(
                "Is MFA required for all users?",
                default=False
            )
            
            print("\nSelect all supported MFA methods (comma-separated numbers):")
            print("  1. SMS/Text message")
            print("  2. TOTP (Time-based One-Time Password, e.g., Google Authenticator)")
            print("  3. WebAuthn/FIDO2 (Security keys, biometrics)")
            print("  4. Push notifications")
            print("  5. Email codes")
            print("  6. Hardware tokens (PIV/CAC)")
            print("  7. Backup codes")
            
            methods_input = self._prompt(
                "Enter numbers (e.g., 1,2,3)",
                default="2,3"
            )
            
            method_map = {
                '1': 'sms',
                '2': 'totp',
                '3': 'webauthn',
                '4': 'push',
                '5': 'email',
                '6': 'piv',
                '7': 'backup_codes'
            }
            
            selected = [m.strip() for m in methods_input.split(',')]
            mfa['supported_authenticator_types'] = [method_map.get(s) for s in selected if s in method_map]
            
            mfa['allows_remember_device'] = self._yes_no(
                "Can users remember/trust devices to skip MFA?",
                default=False
            )
            
            if mfa['allows_remember_device']:
                remember_days = self._prompt(
                    "How many days can a device be remembered?",
                    default="30"
                )
                mfa['remember_device_days'] = int(remember_days) if remember_days.isdigit() else 30
        else:
            mfa['supported_authenticator_types'] = []
        
        return mfa
    
    def collect_session_config(self) -> Dict:
        """Collect session management configuration"""
        print("\n" + "="*70)
        print("SESSION MANAGEMENT CONFIGURATION")
        print("="*70)
        
        session = {}
        
        # Idle timeout
        has_idle_timeout = self._yes_no(
            "Do you have an idle/inactivity timeout?",
            default=False
        )
        
        if has_idle_timeout:
            idle_minutes = self._prompt(
                "Idle timeout in minutes?",
                default="30"
            )
            session['idle_timeout_minutes'] = int(idle_minutes) if idle_minutes.isdigit() else 30
        else:
            session['idle_timeout_minutes'] = 0
        
        # Absolute timeout
        has_max_timeout = self._yes_no(
            "Do you have an absolute session timeout?",
            default=False
        )
        
        if has_max_timeout:
            max_minutes = self._prompt(
                "Maximum session duration in minutes?",
                default="480"
            )
            session['max_session_minutes'] = int(max_minutes) if max_minutes.isdigit() else 480
        else:
            session['max_session_minutes'] = 0
        
        # Session token security
        session['secure_random_tokens'] = self._yes_no(
            "Do you use cryptographically secure random session tokens?",
            default=True
        )
        
        session['httponly_cookies'] = self._yes_no(
            "Are session cookies marked as HttpOnly?",
            default=True
        )
        
        session['secure_cookies'] = self._yes_no(
            "Are session cookies marked as Secure (HTTPS only)?",
            default=True
        )
        
        session['samesite_cookies'] = self._yes_no(
            "Are session cookies using SameSite attribute?",
            default=True
        )
        
        # Reauthentication
        session['reauth_for_sensitive_ops'] = self._yes_no(
            "Do you require reauthentication for sensitive operations?",
            default=False
        )
        
        if session['reauth_for_sensitive_ops']:
            session['sensitive_operations'] = self._prompt(
                "List sensitive operations requiring reauth (comma-separated)",
                default="password change, email change, payment"
            )
        
        # Concurrent sessions
        session['allows_concurrent_sessions'] = self._yes_no(
            "Do you allow concurrent sessions from multiple devices?",
            default=True
        )
        
        if session['allows_concurrent_sessions']:
            max_sessions = self._prompt(
                "Maximum concurrent sessions allowed? (0 for unlimited)",
                default="0"
            )
            session['max_concurrent_sessions'] = int(max_sessions) if max_sessions.isdigit() else 0
        
        return session
    
    def collect_storage_config(self) -> Dict:
        """Collect credential storage configuration"""
        print("\n" + "="*70)
        print("CREDENTIAL STORAGE CONFIGURATION")
        print("="*70)
        
        storage = {}
        
        # Password hashing
        print("\nSelect password hashing algorithm:")
        hash_options = [
            "PBKDF2",
            "bcrypt",
            "scrypt",
            "Argon2",
            "SHA-256 (not recommended)",
            "SHA-512 (not recommended)",
            "MD5 (not recommended)",
            "Other"
        ]
        
        hash_choice = self._prompt(
            "Which hashing algorithm do you use?",
            options=hash_options,
            default="Argon2"
        )
        storage['password_hash_algorithm'] = hash_choice.lower()
        
        if hash_choice == "Other":
            storage['password_hash_algorithm'] = self._prompt(
                "Specify the hashing algorithm",
                default="unknown"
            )
        
        # Salt
        storage['uses_salt'] = self._yes_no(
            "Do you use unique salts for each password?",
            default=True
        )
        
        if storage['uses_salt']:
            salt_length = self._prompt(
                "Salt length in bytes?",
                default="16"
            )
            storage['salt_length_bytes'] = int(salt_length) if salt_length.isdigit() else 16
        
        # Pepper
        storage['uses_pepper'] = self._yes_no(
            "Do you use a pepper (secret key) in addition to salt?",
            default=False
        )
        
        # Encryption at rest
        storage['encrypted_at_rest'] = self._yes_no(
            "Is the credential database encrypted at rest?",
            default=False
        )
        
        if storage['encrypted_at_rest']:
            encryption_method = self._prompt(
                "What encryption method is used? (e.g., AES-256)",
                default="AES-256"
            )
            storage['encryption_method'] = encryption_method
        
        # Key management
        storage['uses_key_management_system'] = self._yes_no(
            "Do you use a key management system (KMS)?",
            default=False
        )
        
        if storage['uses_key_management_system']:
            storage['kms_provider'] = self._prompt(
                "Which KMS provider? (e.g., AWS KMS, Azure Key Vault, HashiCorp Vault)",
                default="N/A"
            )
        
        # Database access controls
        storage['has_database_access_controls'] = self._yes_no(
            "Are there strict access controls on the credential database?",
            default=True
        )
        
        return storage
    
    def collect_transport_config(self) -> Dict:
        """Collect transport security configuration"""
        print("\n" + "="*70)
        print("TRANSPORT SECURITY CONFIGURATION")
        print("="*70)
        
        transport = {}
        
        # TLS usage
        transport['uses_tls'] = self._yes_no(
            "Do you use TLS/HTTPS for all authentication endpoints?",
            default=True
        )
        
        if transport['uses_tls']:
            print("\nSelect minimum TLS version:")
            tls_options = ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
            tls_version = self._prompt(
                "Minimum TLS version?",
                options=tls_options,
                default="TLS 1.2"
            )
            transport['min_tls_version'] = tls_version.split()[-1]  # Extract version number
            
            transport['validates_certificates'] = self._yes_no(
                "Do you validate TLS certificates?",
                default=True
            )
            
            transport['uses_hsts'] = self._yes_no(
                "Do you use HTTP Strict Transport Security (HSTS)?",
                default=False
            )
            
            if transport['uses_hsts']:
                hsts_age = self._prompt(
                    "HSTS max-age in seconds?",
                    default="31536000"
                )
                transport['hsts_max_age'] = int(hsts_age) if hsts_age.isdigit() else 31536000
            
            transport['certificate_pinning'] = self._yes_no(
                "Do you use certificate pinning?",
                default=False
            )
        
        # API security
        transport['uses_api_authentication'] = self._yes_no(
            "Do APIs require authentication?",
            default=True
        )
        
        if transport['uses_api_authentication']:
            print("\nSelect API authentication method:")
            api_auth_options = [
                "OAuth 2.0",
                "JWT (JSON Web Tokens)",
                "API Keys",
                "Basic Auth",
                "Other"
            ]
            api_auth = self._prompt(
                "API authentication method?",
                options=api_auth_options,
                default="OAuth 2.0"
            )
            transport['api_auth_method'] = api_auth
        
        return transport
    
    def collect_privacy_config(self) -> Dict:
        """Collect privacy configuration"""
        print("\n" + "="*70)
        print("PRIVACY & DATA PROTECTION CONFIGURATION")
        print("="*70)
        
        privacy = {}
        
        # Privacy notice
        privacy['has_privacy_notice'] = self._yes_no(
            "Do you provide a privacy notice/policy?",
            default=True
        )
        
        if privacy['has_privacy_notice']:
            privacy['privacy_notice_url'] = self._prompt(
                "Privacy notice URL (optional)",
                default=""
            )
        
        # Consent
        privacy['obtains_consent'] = self._yes_no(
            "Do you obtain explicit user consent for data collection?",
            default=True
        )
        
        # Data minimization
        privacy['data_minimization'] = self._yes_no(
            "Do you practice data minimization (collect only necessary data)?",
            default=True
        )
        
        # PII handling
        privacy['collects_pii'] = self._yes_no(
            "Do you collect Personally Identifiable Information (PII)?",
            default=True
        )
        
        if privacy['collects_pii']:
            print("\nWhat types of PII do you collect? (comma-separated)")
            print("Examples: name, email, phone, address, SSN, date of birth")
            pii_types = self._prompt(
                "PII types",
                default="name, email"
            )
            privacy['pii_types_collected'] = [p.strip() for p in pii_types.split(',')]
        
        # Data retention
        privacy['has_data_retention_policy'] = self._yes_no(
            "Do you have a data retention policy?",
            default=False
        )
        
        if privacy['has_data_retention_policy']:
            retention_period = self._prompt(
                "Data retention period (e.g., '2 years', '90 days')",
                default="2 years"
            )
            privacy['data_retention_period'] = retention_period
        
        # User rights
        privacy['allows_data_export'] = self._yes_no(
            "Can users export their data?",
            default=False
        )
        
        privacy['allows_data_deletion'] = self._yes_no(
            "Can users request data deletion?",
            default=False
        )
        
        # Third-party sharing
        privacy['shares_data_with_third_parties'] = self._yes_no(
            "Do you share data with third parties?",
            default=False
        )
        
        if privacy['shares_data_with_third_parties']:
            third_parties = self._prompt(
                "List third parties (comma-separated)",
                default=""
            )
            privacy['third_parties'] = [p.strip() for p in third_parties.split(',') if p.strip()]
        
        return privacy
    
    def collect_recovery_config(self) -> Dict:
        """Collect account recovery configuration"""
        print("\n" + "="*70)
        print("ACCOUNT RECOVERY CONFIGURATION")
        print("="*70)
        
        recovery = {}
        
        recovery['has_recovery_mechanism'] = self._yes_no(
            "Do you provide account recovery mechanisms?",
            default=True
        )
        
        if recovery['has_recovery_mechanism']:
            print("\nSelect all recovery methods available (comma-separated numbers):")
            print("  1. Email link/code")
            print("  2. SMS code")
            print("  3. Security questions")
            print("  4. Backup codes")
            print("  5. Authenticator app")
            print("  6. Support contact")
            print("  7. Other")
            
            methods_input = self._prompt(
                "Enter numbers (e.g., 1,4,5)",
                default="1,4"
            )
            
            method_map = {
                '1': 'email_link',
                '2': 'sms_code',
                '3': 'security_questions',
                '4': 'backup_codes',
                '5': 'authenticator_app',
                '6': 'support_contact',
                '7': 'other'
            }
            
            selected = [m.strip() for m in methods_input.split(',')]
            recovery['recovery_methods'] = [method_map.get(s) for s in selected if s in method_map]
            
            # Security questions (if selected)
            if 'security_questions' in recovery['recovery_methods']:
                num_questions = self._prompt(
                    "How many security questions are required?",
                    default="3"
                )
                recovery['num_security_questions'] = int(num_questions) if num_questions.isdigit() else 3
            
            # Recovery link expiration
            recovery['recovery_link_expires'] = self._yes_no(
                "Do recovery links expire?",
                default=True
            )
            
            if recovery['recovery_link_expires']:
                expiration_minutes = self._prompt(
                    "Recovery link expiration time in minutes?",
                    default="60"
                )
                recovery['recovery_link_expiration_minutes'] = int(expiration_minutes) if expiration_minutes.isdigit() else 60
            
            # Rate limiting on recovery
            recovery['recovery_rate_limited'] = self._yes_no(
                "Is account recovery rate-limited?",
                default=True
            )
        
        return recovery
    
    def collect_identity_proofing_config(self) -> Dict:
        """Collect identity proofing configuration (for IAL2/IAL3)"""
        print("\n" + "="*70)
        print("IDENTITY PROOFING CONFIGURATION")
        print("="*70)
        
        identity = {}
        
        identity['performs_identity_proofing'] = self._yes_no(
            "Do you perform identity proofing (verify user identity)?",
            default=False
        )
        
        if identity['performs_identity_proofing']:
            print("\nSelect identity proofing methods (comma-separated numbers):")
            print("  1. Government-issued ID verification")
            print("  2. Biometric verification")
            print("  3. In-person proofing")
            print("  4. Remote video proofing")
            print("  5. Knowledge-based verification")
            print("  6. Third-party identity service")
            
            methods_input = self._prompt(
                "Enter numbers (e.g., 1,6)",
                default="1"
            )
            
            method_map = {
                '1': 'government_id',
                '2': 'biometric',
                '3': 'in_person',
                '4': 'remote_video',
                '5': 'knowledge_based',
                '6': 'third_party_service'
            }
            
            selected = [m.strip() for m in methods_input.split(',')]
            identity['proofing_methods'] = [method_map.get(s) for s in selected if s in method_map]
            
            identity['verifies_address'] = self._yes_no(
                "Do you verify user address?",
                default=False
            )
            
            identity['uses_trusted_referee'] = self._yes_no(
                "Do you use trusted referees for identity proofing?",
                default=False
            )
        
        return identity
    
    def collect_all_configurations(self) -> Dict:
        """Collect all system configurations"""
        print("\n" + "="*70)
        print("NIST 800-63-4 COMPLIANCE AUDIT - CONFIGURATION COLLECTOR")
        print("="*70)
        print("\nThis tool will collect information about your authentication system")
        print("to perform a comprehensive NIST 800-63-4 compliance audit.")
        print("\nPress Ctrl+C at any time to cancel.")
        
        try:
            # Collect target assurance levels
            print("\n" + "="*70)
            print("TARGET ASSURANCE LEVELS")
            print("="*70)
            
            aal_choice = self._prompt(
                "Target Authentication Assurance Level (AAL)?",
                options=["AAL1", "AAL2", "AAL3"],
                default="AAL2"
            )
            
            ial_choice = self._prompt(
                "Target Identity Assurance Level (IAL)?",
                options=["IAL1", "IAL2", "IAL3"],
                default="IAL1"
            )
            
            fal_choice = self._prompt(
                "Target Federation Assurance Level (FAL)?",
                options=["FAL1", "FAL2", "FAL3"],
                default="FAL1"
            )
            
            config = {
                'target_levels': {
                    'aal': aal_choice,
                    'ial': ial_choice,
                    'fal': fal_choice
                },
                'password_policy': self.collect_password_policy(),
                'mfa_config': self.collect_mfa_config(),
                'session_config': self.collect_session_config(),
                'storage_config': self.collect_storage_config(),
                'transport_config': self.collect_transport_config(),
                'privacy_config': self.collect_privacy_config(),
                'recovery_config': self.collect_recovery_config(),
                'identity_proofing_config': self.collect_identity_proofing_config()
            }
            
            # Save configuration
            save_config = self._yes_no(
                "\nWould you like to save this configuration for future audits?",
                default=True
            )
            
            if save_config:
                filename = self._prompt(
                    "Configuration filename",
                    default="nist_audit_config.json"
                )
                self.save_configuration(config, filename)
                print(f"\n✓ Configuration saved to: {filename}")
            
            return config
            
        except KeyboardInterrupt:
            print("\n\nConfiguration collection cancelled.")
            sys.exit(0)
    
    def save_configuration(self, config: Dict, filename: str):
        """Save configuration to JSON file"""
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
    
    def load_configuration(self, filename: str) -> Dict:
        """Load configuration from JSON file"""
        with open(filename, 'r') as f:
            return json.load(f)


class NIST80063Auditor:
    """Main auditor class for NIST 800-63-4 compliance"""
    
    def __init__(self, target_aal: AAL = AAL.AAL2, target_ial: IAL = IAL.IAL1, target_fal: FAL = FAL.FAL1):
        self.target_aal = target_aal
        self.target_ial = target_ial
        self.target_fal = target_fal
        self.results: List[AuditResult] = []
    
    def audit_password_requirements(self, password_policy: Dict) -> List[AuditResult]:
        """Audit password/memorized secret requirements"""
        results = []
        
        # Check minimum length (8 characters minimum)
        min_length = password_policy.get('min_length', 0)
        results.append(AuditResult(
            check_id="AAL-PWD-001",
            category="Password Requirements",
            requirement="Minimum password length of 8 characters",
            status="PASS" if min_length >= 8 else "FAIL",
            details=f"Current minimum length: {min_length}",
            severity="CRITICAL" if min_length < 8 else "LOW",
            remediation="Set minimum password length to at least 8 characters"
        ))
        
        # Check maximum length (at least 64 characters)
        max_length = password_policy.get('max_length', 0)
        results.append(AuditResult(
            check_id="AAL-PWD-002",
            category="Password Requirements",
            requirement="Maximum password length of at least 64 characters",
            status="PASS" if max_length >= 64 else "FAIL",
            details=f"Current maximum length: {max_length}",
            severity="HIGH" if max_length < 64 else "LOW",
            remediation="Allow passwords up to at least 64 characters"
        ))
        
        # Check for composition rules (should NOT be required)
        has_composition_rules = password_policy.get('requires_complexity', False)
        results.append(AuditResult(
            check_id="AAL-PWD-003",
            category="Password Requirements",
            requirement="No mandatory composition rules (e.g., requiring special characters)",
            status="FAIL" if has_composition_rules else "PASS",
            details=f"Composition rules enforced: {has_composition_rules}",
            severity="MEDIUM" if has_composition_rules else "LOW",
            remediation="Remove mandatory composition rules; rely on length and breach checking"
        ))
        
        # Check for password breach detection
        has_breach_check = password_policy.get('checks_breached_passwords', False)
        results.append(AuditResult(
            check_id="AAL-PWD-004",
            category="Password Requirements",
            requirement="Check passwords against breach databases",
            status="PASS" if has_breach_check else "FAIL",
            details=f"Breach checking enabled: {has_breach_check}",
            severity="CRITICAL" if not has_breach_check else "LOW",
            remediation="Implement checking against known breached password databases"
        ))
        
        # Check for password expiration (should NOT be required)
        has_expiration = password_policy.get('password_expiration_days', 0) > 0
        results.append(AuditResult(
            check_id="AAL-PWD-005",
            category="Password Requirements",
            requirement="No arbitrary password expiration",
            status="FAIL" if has_expiration else "PASS",
            details=f"Password expiration: {password_policy.get('password_expiration_days', 'None')} days",
            severity="MEDIUM" if has_expiration else "LOW",
            remediation="Remove arbitrary password expiration; only require change on compromise"
        ))
        
        # Check for rate limiting
        has_rate_limiting = password_policy.get('rate_limiting_enabled', False)
        results.append(AuditResult(
            check_id="AAL-PWD-006",
            category="Password Requirements",
            requirement="Rate limiting on authentication attempts",
            status="PASS" if has_rate_limiting else "FAIL",
            details=f"Rate limiting enabled: {has_rate_limiting}",
            severity="CRITICAL" if not has_rate_limiting else "LOW",
            remediation="Implement rate limiting to prevent brute force attacks"
        ))
        
        return results
    
    def audit_mfa_requirements(self, mfa_config: Dict) -> List[AuditResult]:
        """Audit multi-factor authentication requirements for AAL2/AAL3"""
        results = []
        
        if self.target_aal.value >= AAL.AAL2.value:
            # Check if MFA is enabled
            mfa_enabled = mfa_config.get('enabled', False)
            results.append(AuditResult(
                check_id="AAL-MFA-001",
                category="Multi-Factor Authentication",
                requirement=f"MFA required for {self.target_aal.name}",
                status="PASS" if mfa_enabled else "FAIL",
                details=f"MFA enabled: {mfa_enabled}",
                severity="CRITICAL" if not mfa_enabled else "LOW",
                remediation="Enable multi-factor authentication"
            ))
            
            # Check supported authenticator types
            supported_types = mfa_config.get('supported_authenticator_types', [])
            has_phishing_resistant = any(t in supported_types for t in ['webauthn', 'fido2', 'piv', 'cac'])
            
            if self.target_aal == AAL.AAL3:
                results.append(AuditResult(
                    check_id="AAL-MFA-002",
                    category="Multi-Factor Authentication",
                    requirement="AAL3 requires phishing-resistant authenticators",
                    status="PASS" if has_phishing_resistant else "FAIL",
                    details=f"Supported types: {', '.join(supported_types)}",
                    severity="CRITICAL" if not has_phishing_resistant else "LOW",
                    remediation="Implement WebAuthn/FIDO2 or hardware cryptographic authenticators"
                ))
            
            # Check for SMS as sole factor (discouraged)
            uses_sms_only = 'sms' in supported_types and len(supported_types) == 1
            results.append(AuditResult(
                check_id="AAL-MFA-003",
                category="Multi-Factor Authentication",
                requirement="SMS should not be the only MFA option",
                status="WARNING" if uses_sms_only else "PASS",
                details=f"SMS-only MFA: {uses_sms_only}",
                severity="MEDIUM" if uses_sms_only else "LOW",
                remediation="Provide additional MFA options beyond SMS (TOTP, WebAuthn, etc.)"
            ))
        
        return results
    
    def audit_session_management(self, session_config: Dict) -> List[AuditResult]:
        """Audit session management requirements"""
        results = []
        
        # Check session timeout
        idle_timeout = session_config.get('idle_timeout_minutes', 0)
        max_timeout = session_config.get('max_session_minutes', 0)
        
        results.append(AuditResult(
            check_id="AAL-SES-001",
            category="Session Management",
            requirement="Implement session idle timeout",
            status="PASS" if idle_timeout > 0 and idle_timeout <= 30 else "FAIL",
            details=f"Idle timeout: {idle_timeout} minutes",
            severity="HIGH" if idle_timeout == 0 else "MEDIUM",
            remediation="Implement idle timeout of 30 minutes or less for sensitive applications"
        ))
        
        results.append(AuditResult(
            check_id="AAL-SES-002",
            category="Session Management",
            requirement="Implement absolute session timeout",
            status="PASS" if max_timeout > 0 else "WARNING",
            details=f"Max session: {max_timeout} minutes",
            severity="MEDIUM" if max_timeout == 0 else "LOW",
            remediation="Consider implementing absolute session timeout"
        ))
        
        # Check for secure session tokens
        uses_secure_tokens = session_config.get('secure_random_tokens', False)
        results.append(AuditResult(
            check_id="AAL-SES-003",
            category="Session Management",
            requirement="Use cryptographically secure random session identifiers",
            status="PASS" if uses_secure_tokens else "FAIL",
            details=f"Secure tokens: {uses_secure_tokens}",
            severity="CRITICAL" if not uses_secure_tokens else "LOW",
            remediation="Use cryptographically secure random number generator for session tokens"
        ))
        
        # Check for reauthentication on sensitive operations
        requires_reauth = session_config.get('reauth_for_sensitive_ops', False)
        results.append(AuditResult(
            check_id="AAL-SES-004",
            category="Session Management",
            requirement="Require reauthentication for sensitive operations",
            status="PASS" if requires_reauth else "WARNING",
            details=f"Reauthentication required: {requires_reauth}",
            severity="MEDIUM" if not requires_reauth else "LOW",
            remediation="Implement reauthentication for sensitive operations"
        ))
        
        # Check cookie security
        httponly = session_config.get('httponly_cookies', False)
        results.append(AuditResult(
            check_id="AAL-SES-005",
            category="Session Management",
            requirement="Use HttpOnly flag on session cookies",
            status="PASS" if httponly else "FAIL",
            details=f"HttpOnly cookies: {httponly}",
            severity="HIGH" if not httponly else "LOW",
            remediation="Set HttpOnly flag on session cookies to prevent XSS attacks"
        ))
        
        secure_cookies = session_config.get('secure_cookies', False)
        results.append(AuditResult(
            check_id="AAL-SES-006",
            category="Session Management",
            requirement="Use Secure flag on session cookies",
            status="PASS" if secure_cookies else "FAIL",
            details=f"Secure cookies: {secure_cookies}",
            severity="HIGH" if not secure_cookies else "LOW",
            remediation="Set Secure flag on session cookies to ensure HTTPS-only transmission"
        ))
        
        return results
    
    def audit_credential_storage(self, storage_config: Dict) -> List[AuditResult]:
        """Audit credential storage requirements"""
        results = []
        
        # Check password hashing
        hash_algorithm = storage_config.get('password_hash_algorithm', '').lower()
        approved_algorithms = ['pbkdf2', 'bcrypt', 'scrypt', 'argon2']
        uses_approved_hash = any(alg in hash_algorithm for alg in approved_algorithms)
        
        results.append(AuditResult(
            check_id="AAL-STO-001",
            category="Credential Storage",
            requirement="Use approved password hashing algorithm",
            status="PASS" if uses_approved_hash else "FAIL",
            details=f"Hash algorithm: {hash_algorithm}",
            severity="CRITICAL" if not uses_approved_hash else "LOW",
            remediation="Use PBKDF2, bcrypt, scrypt, or Argon2 for password hashing"
        ))
        
        # Check for salt
        uses_salt = storage_config.get('uses_salt', False)
        results.append(AuditResult(
            check_id="AAL-STO-002",
            category="Credential Storage",
            requirement="Use unique salt for each password",
            status="PASS" if uses_salt else "FAIL",
            details=f"Uses salt: {uses_salt}",
            severity="CRITICAL" if not uses_salt else "LOW",
            remediation="Implement unique salt for each password hash"
        ))
        
        # Check encryption at rest
        encrypted_at_rest = storage_config.get('encrypted_at_rest', False)
        results.append(AuditResult(
            check_id="AAL-STO-003",
            category="Credential Storage",
            requirement="Encrypt sensitive data at rest",
            status="PASS" if encrypted_at_rest else "WARNING",
            details=f"Encryption at rest: {encrypted_at_rest}",
            severity="HIGH" if not encrypted_at_rest else "LOW",
            remediation="Implement encryption at rest for credential databases"
        ))
        
        # Check key management
        uses_kms = storage_config.get('uses_key_management_system', False)
        results.append(AuditResult(
            check_id="AAL-STO-004",
            category="Credential Storage",
            requirement="Use proper key management system",
            status="PASS" if uses_kms else "WARNING",
            details=f"Uses KMS: {uses_kms}",
            severity="MEDIUM" if not uses_kms else "LOW",
            remediation="Implement a key management system for encryption keys"
        ))
        
        return results
    
    def audit_transport_security(self, transport_config: Dict) -> List[AuditResult]:
        """Audit transport security requirements"""
        results = []
        
        # Check TLS usage
        uses_tls = transport_config.get('uses_tls', False)
        tls_version = transport_config.get('min_tls_version', '')
        
        results.append(AuditResult(
            check_id="AAL-TLS-001",
            category="Transport Security",
            requirement="Use TLS for all authentication communications",
            status="PASS" if uses_tls else "FAIL",
            details=f"TLS enabled: {uses_tls}",
            severity="CRITICAL" if not uses_tls else "LOW",
            remediation="Enable TLS for all authentication endpoints"
        ))
        
        results.append(AuditResult(
            check_id="AAL-TLS-002",
            category="Transport Security",
            requirement="Use TLS 1.2 or higher",
            status="PASS" if tls_version >= '1.2' else "FAIL",
            details=f"Minimum TLS version: {tls_version}",
            severity="CRITICAL" if tls_version < '1.2' else "LOW",
            remediation="Configure minimum TLS version to 1.2 or 1.3"
        ))
        
        # Check certificate validation
        validates_certs = transport_config.get('validates_certificates', False)
        results.append(AuditResult(
            check_id="AAL-TLS-003",
            category="Transport Security",
            requirement="Validate TLS certificates",
            status="PASS" if validates_certs else "FAIL",
            details=f"Certificate validation: {validates_certs}",
            severity="CRITICAL" if not validates_certs else "LOW",
            remediation="Enable and enforce TLS certificate validation"
        ))
        
        # Check HSTS
        uses_hsts = transport_config.get('uses_hsts', False)
        results.append(AuditResult(
            check_id="AAL-TLS-004",
            category="Transport Security",
            requirement="Use HTTP Strict Transport Security (HSTS)",
            status="PASS" if uses_hsts else "WARNING",
            details=f"HSTS enabled: {uses_hsts}",
            severity="MEDIUM" if not uses_hsts else "LOW",
            remediation="Enable HSTS to prevent protocol downgrade attacks"
        ))
        
        return results
    
    def audit_privacy_requirements(self, privacy_config: Dict) -> List[AuditResult]:
        """Audit privacy and data minimization requirements"""
        results = []
        
        # Check for privacy notice
        has_privacy_notice = privacy_config.get('has_privacy_notice', False)
        results.append(AuditResult(
            check_id="IAL-PRI-001",
            category="Privacy",
            requirement="Provide clear privacy notice",
            status="PASS" if has_privacy_notice else "FAIL",
            details=f"Privacy notice provided: {has_privacy_notice}",
            severity="HIGH" if not has_privacy_notice else "LOW",
            remediation="Provide clear privacy notice explaining data collection and use"
        ))
        
        # Check for consent mechanism
        has_consent = privacy_config.get('obtains_consent', False)
        results.append(AuditResult(
            check_id="IAL-PRI-002",
            category="Privacy",
            requirement="Obtain user consent for data collection",
            status="PASS" if has_consent else "FAIL",
            details=f"Consent obtained: {has_consent}",
            severity="HIGH" if not has_consent else "LOW",
            remediation="Implement consent mechanism for data collection"
        ))
        
        # Check data minimization
        practices_minimization = privacy_config.get('data_minimization', False)
        results.append(AuditResult(
            check_id="IAL-PRI-003",
            category="Privacy",
            requirement="Practice data minimization",
            status="PASS" if practices_minimization else "WARNING",
            details=f"Data minimization practiced: {practices_minimization}",
            severity="MEDIUM" if not practices_minimization else "LOW",
            remediation="Collect only necessary data for authentication purposes"
        ))
        
        # Check data retention policy
        has_retention = privacy_config.get('has_data_retention_policy', False)
        results.append(AuditResult(
            check_id="IAL-PRI-004",
            category="Privacy",
            requirement="Implement data retention policy",
            status="PASS" if has_retention else "WARNING",
            details=f"Data retention policy: {has_retention}",
            severity="MEDIUM" if not has_retention else "LOW",
            remediation="Establish and document data retention policies"
        ))
        
        # Check user rights
        allows_export = privacy_config.get('allows_data_export', False)
        allows_deletion = privacy_config.get('allows_data_deletion', False)
        
        results.append(AuditResult(
            check_id="IAL-PRI-005",
            category="Privacy",
            requirement="Support user data rights (export/deletion)",
            status="PASS" if (allows_export and allows_deletion) else "WARNING",
            details=f"Data export: {allows_export}, Data deletion: {allows_deletion}",
            severity="MEDIUM" if not (allows_export and allows_deletion) else "LOW",
            remediation="Implement mechanisms for users to export and delete their data"
        ))
        
        return results
    
    def audit_account_recovery(self, recovery_config: Dict) -> List[AuditResult]:
        """Audit account recovery mechanisms"""
        results = []
        
        # Check for secure recovery mechanism
        has_recovery = recovery_config.get('has_recovery_mechanism', False)
        results.append(AuditResult(
            check_id="AAL-REC-001",
            category="Account Recovery",
            requirement="Provide secure account recovery mechanism",
            status="PASS" if has_recovery else "WARNING",
            details=f"Recovery mechanism available: {has_recovery}",
            severity="MEDIUM" if not has_recovery else "LOW",
            remediation="Implement secure account recovery process"
        ))
        
        # Check recovery method security
        recovery_methods = recovery_config.get('recovery_methods', [])
        uses_secure_recovery = any(m in recovery_methods for m in ['email_link', 'authenticator_app', 'backup_codes'])
        
        results.append(AuditResult(
            check_id="AAL-REC-002",
            category="Account Recovery",
            requirement="Use secure recovery methods",
            status="PASS" if uses_secure_recovery else "WARNING",
            details=f"Recovery methods: {', '.join(recovery_methods) if recovery_methods else 'None'}",
            severity="MEDIUM" if not uses_secure_recovery else "LOW",
            remediation="Use secure recovery methods like email links or backup codes"
        ))
        
        # Check for security questions (discouraged)
        uses_security_questions = 'security_questions' in recovery_methods
        results.append(AuditResult(
            check_id="AAL-REC-003",
            category="Account Recovery",
            requirement="Avoid using security questions as sole recovery method",
            status="WARNING" if uses_security_questions else "PASS",
            details=f"Uses security questions: {uses_security_questions}",
            severity="MEDIUM" if uses_security_questions else "LOW",
            remediation="Security questions are weak; use stronger recovery methods"
        ))
        
        # Check recovery link expiration
        link_expires = recovery_config.get('recovery_link_expires', False)
        results.append(AuditResult(
            check_id="AAL-REC-004",
            category="Account Recovery",
            requirement="Recovery links should expire",
            status="PASS" if link_expires else "WARNING",
            details=f"Recovery links expire: {link_expires}",
            severity="MEDIUM" if not link_expires else "LOW",
            remediation="Implement expiration for recovery links (e.g., 1 hour)"
        ))
        
        # Check rate limiting
        rate_limited = recovery_config.get('recovery_rate_limited', False)
        results.append(AuditResult(
            check_id="AAL-REC-005",
            category="Account Recovery",
            requirement="Rate limit recovery attempts",
            status="PASS" if rate_limited else "FAIL",
            details=f"Recovery rate limited: {rate_limited}",
            severity="HIGH" if not rate_limited else "LOW",
            remediation="Implement rate limiting on account recovery to prevent abuse"
        ))
        
        return results
    
    def run_full_audit(self, config: Dict) -> Dict:
        """Run complete NIST 800-63-4 audit"""
        self.results = []
        
        # Run all audit checks
        self.results.extend(self.audit_password_requirements(config.get('password_policy', {})))
        self.results.extend(self.audit_mfa_requirements(config.get('mfa_config', {})))
        self.results.extend(self.audit_session_management(config.get('session_config', {})))
        self.results.extend(self.audit_credential_storage(config.get('storage_config', {})))
        self.results.extend(self.audit_transport_security(config.get('transport_config', {})))
        self.results.extend(self.audit_privacy_requirements(config.get('privacy_config', {})))
        self.results.extend(self.audit_account_recovery(config.get('recovery_config', {})))
        
        # Generate summary
        summary = self._generate_summary()
        
        return {
            'audit_date': datetime.now().isoformat(),
            'target_aal': self.target_aal.name,
            'target_ial': self.target_ial.name,
            'target_fal': self.target_fal.name,
            'summary': summary,
            'results': [asdict(r) for r in self.results]
        }
    
    def _generate_summary(self) -> Dict:
        """Generate audit summary statistics"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == 'PASS')
        failed = sum(1 for r in self.results if r.status == 'FAIL')
        warnings = sum(1 for r in self.results if r.status == 'WARNING')
        
        critical = sum(1 for r in self.results if r.severity == 'CRITICAL' and r.status == 'FAIL')
        high = sum(1 for r in self.results if r.severity == 'HIGH' and r.status == 'FAIL')
        
        # Group by category
        by_category = {}
        for result in self.results:
            if result.category not in by_category:
                by_category[result.category] = {'passed': 0, 'failed': 0, 'warnings': 0}
            
            if result.status == 'PASS':
                by_category[result.category]['passed'] += 1
            elif result.status == 'FAIL':
                by_category[result.category]['failed'] += 1
            elif result.status == 'WARNING':
                by_category[result.category]['warnings'] += 1
        
        return {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'compliance_percentage': round((passed / total * 100) if total > 0 else 0, 2),
            'critical_failures': critical,
            'high_failures': high,
            'overall_status': 'COMPLIANT' if failed == 0 and critical == 0 else 'NON_COMPLIANT',
            'by_category': by_category
        }
    
    def generate_report(self, config: Dict, output_file: str = 'nist_audit_report.json'):
        """Generate JSON audit report"""
        report = self.run_full_audit(config)
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        return output_file
    
    def print_summary(self):
        """Print audit summary to console"""
        if not self.results:
            print("No audit results available. Run audit first.")
            return
        
        summary = self._generate_summary()
        
        print("\n" + "="*70)
        print("NIST 800-63-4 COMPLIANCE AUDIT REPORT")
        print("="*70)
        print(f"Target AAL: {self.target_aal.name}")
        print(f"Target IAL: {self.target_ial.name}")
        print(f"Target FAL: {self.target_fal.name}")
        print(f"Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        print(f"\nOVERALL STATUS: {summary['overall_status']}")
        print(f"Compliance: {summary['compliance_percentage']}%")
        print(f"\nTotal Checks: {summary['total_checks']}")
        print(f"✓ Passed: {summary['passed']}")
        print(f"✗ Failed: {summary['failed']}")
        print(f"⚠ Warnings: {summary['warnings']}")
        print(f"\n🔴 Critical Failures: {summary['critical_failures']}")
        print(f"🟠 High Severity Failures: {summary['high_failures']}")
        
        # Print by category
        print("\n" + "="*70)
        print("RESULTS BY CATEGORY")
        print("="*70)
        for category, stats in summary['by_category'].items():
            print(f"\n{category}:")
            print(f"  ✓ Passed: {stats['passed']}")
            print(f"  ✗ Failed: {stats['failed']}")
            print(f"  ⚠ Warnings: {stats['warnings']}")
        
        # Print failed checks
        failed_checks = [r for r in self.results if r.status == 'FAIL']
        if failed_checks:
            print("\n" + "="*70)
            print("FAILED CHECKS")
            print("="*70)
            for check in failed_checks:
                print(f"\n[{check.severity}] {check.check_id}: {check.requirement}")
                print(f"  Category: {check.category}")
                print(f"  Details: {check.details}")
                print(f"  Remediation: {check.remediation}")
        
        # Print warnings
        warning_checks = [r for r in self.results if r.status == 'WARNING']
        if warning_checks:
            print("\n" + "="*70)
            print("WARNINGS")
            print("="*70)
            for check in warning_checks:
                print(f"\n[{check.severity}] {check.check_id}: {check.requirement}")
                print(f"  Category: {check.category}")
                print(f"  Details: {check.details}")
                print(f"  Remediation: {check.remediation}")


# Main execution
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='NIST 800-63-4 Compliance Audit Tool')
    parser.add_argument('--config', '-c', help='Load configuration from file')
    parser.add_argument('--interactive', '-i', action='store_true', help='Run interactive configuration collector')
    parser.add_argument('--output', '-o', default='nist_audit_report.json', help='Output report filename')
    parser.add_argument('--aal', choices=['AAL1', 'AAL2', 'AAL3'], default='AAL2', help='Target AAL level')
    parser.add_argument('--ial', choices=['IAL1', 'IAL2', 'IAL3'], default='IAL1', help='Target IAL level')
    parser.add_argument('--fal', choices=['FAL1', 'FAL2', 'FAL3'], default='FAL1', help='Target FAL level')
    
    args = parser.parse_args()
    
    # Collect or load configuration
    if args.interactive or not args.config:
        collector = ConfigurationCollector(interactive=True)
        config = collector.collect_all_configurations()
        
        # Extract target levels from config
        target_levels = config.get('target_levels', {})
        aal = AAL[target_levels.get('aal', 'AAL2')]
        ial = IAL[target_levels.get('ial', 'IAL1')]
        fal = FAL[target_levels.get('fal', 'FAL1')]
    else:
        collector = ConfigurationCollector(interactive=False)
        config = collector.load_configuration(args.config)
        aal = AAL[args.aal]
        ial = IAL[args.ial]
        fal = FAL[args.fal]
        print(f"\n✓ Configuration loaded from: {args.config}")
    
    # Create auditor and run audit
    auditor = NIST80063Auditor(target_aal=aal, target_ial=ial, target_fal=fal)
    
    print("\n" + "="*70)
    print("RUNNING AUDIT...")
    print("="*70)
    
    report = auditor.run_full_audit(config)
    
    # Print summary
    auditor.print_summary()
    
    # Save detailed report
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n\n✓ Detailed report saved to: {args.output}")
    
    # Exit with appropriate code
    sys.exit(0 if report['summary']['overall_status'] == 'COMPLIANT' else 1)