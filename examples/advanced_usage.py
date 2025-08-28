"""
Advanced Example - SecureTokenManager

This advanced example demonstrates:
- Custom secret keys and salts
- Multiple users and permission management
- Token refresh and cleanup
- Batch operations
- Error handling and logging
- Performance testing
- Configuration management

Author: AmirHossein Babaee
Date: 2025
"""

import time
import json
from datetime import datetime
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.secure_token import SecureTokenManager
from src.secure_token import (
    TokenError, TokenExpiredError, TokenRevokedError, 
    InvalidTokenError, PermissionDeniedError
)


class TokenManagementSystem:
    """Advanced token management system with multiple features"""
    
    def __init__(self, custom_secret: str = None):
        """Initialize with custom configuration"""
        # Initialize with custom secret key and salt
        custom_salt = b'advanced_secure_salt_2025_production'
        
        self.manager = SecureTokenManager(
            secret_key=custom_secret or "MyAdvancedSecretKey2025!@#",
            salt=custom_salt
        )
        
        # User roles and permissions mapping
        self.user_roles = {
            "admin": ["read", "write", "delete", "manage_users", "system_config"],
            "manager": ["read", "write", "delete", "manage_team"],
            "editor": ["read", "write", "create_content"],
            "viewer": ["read", "view_reports"],
            "guest": ["read_public"]
        }
        
        # Store active sessions
        self.user_sessions = {}
    
    def create_user_session(self, user_id: str, role: str, 
                          session_duration: int = 8, 
                          additional_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a comprehensive user session with role-based permissions"""
        
        print(f"\n🔐 Creating session for user: {user_id} (Role: {role})")
        
        try:
            # Get permissions based on role
            permissions = self.user_roles.get(role, ["read"])
            
            # Add additional metadata
            session_data = additional_data or {}
            session_data.update({
                "role": role,
                "login_time": datetime.now().isoformat(),
                "ip_address": "192.168.1.100",  # Example IP
                "user_agent": "Advanced-Token-System/1.0",
                "session_type": "web_application"
            })
            
            # Generate token
            token = self.manager.generate_token(
                user_id=user_id,
                permissions=permissions,
                expires_in_hours=session_duration,
                additional_data=session_data,
                max_tokens_per_user=5  # Allow up to 5 concurrent sessions
            )
            
            # Store session info
            session_info = {
                "token": token,
                "user_id": user_id,
                "role": role,
                "permissions": permissions,
                "created_at": datetime.now(),
                "expires_in_hours": session_duration,
                "additional_data": session_data
            }
            
            if user_id not in self.user_sessions:
                self.user_sessions[user_id] = []
            self.user_sessions[user_id].append(session_info)
            
            print(f"✅ Session created successfully")
            print(f"   Permissions: {permissions}")
            print(f"   Duration: {session_duration} hours")
            print(f"   Additional data keys: {list(session_data.keys())}")
            
            return session_info
            
        except Exception as e:
            print(f"❌ Error creating session: {e}")
            raise
    
    def batch_create_users(self, users_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create multiple user sessions simultaneously"""
        
        print(f"\n🚀 Creating {len(users_data)} user sessions in batch...")
        
        sessions = []
        start_time = time.time()
        
        # Use ThreadPoolExecutor for concurrent token generation
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_user = {
                executor.submit(
                    self.create_user_session,
                    user['user_id'],
                    user['role'],
                    user.get('duration', 8),
                    user.get('additional_data')
                ): user for user in users_data
            }
            
            for future in as_completed(future_to_user):
                user = future_to_user[future]
                try:
                    session = future.result()
                    sessions.append(session)
                except Exception as e:
                    print(f"❌ Failed to create session for {user['user_id']}: {e}")
        
        end_time = time.time()
        print(f"✅ Batch creation completed in {end_time - start_time:.2f} seconds")
        print(f"   Successfully created: {len(sessions)} sessions")
        
        return sessions
    
    def validate_and_authorize(self, token: str, required_permission: str) -> Dict[str, Any]:
        """Validate token and check authorization for specific action"""
        
        try:
            # Validate token
            validation_result = self.manager.validate_token(token)
            
            # Check permission
            self.manager.check_permission(token, required_permission)
            
            # Get additional session info
            user_id = validation_result['user_id']
            additional_data = validation_result['additional_data']
            
            print(f"🔓 Access granted for user {user_id}")
            print(f"   Permission: {required_permission}")
            print(f"   Role: {additional_data.get('role', 'Unknown')}")
            print(f"   Session type: {additional_data.get('session_type', 'Unknown')}")
            
            return {
                "authorized": True,
                "user_info": validation_result,
                "session_data": additional_data
            }
            
        except (TokenExpiredError, TokenRevokedError, InvalidTokenError) as e:
            print(f"🚫 Authentication failed: {e}")
            return {"authorized": False, "error": str(e)}
        except PermissionDeniedError as e:
            print(f"🚫 Authorization failed: {e}")
            return {"authorized": False, "error": str(e)}
    
    def refresh_user_sessions(self, user_id: str, extend_hours: int = 8) -> List[str]:
        """Refresh all active sessions for a user"""
        
        print(f"\n🔄 Refreshing sessions for user: {user_id}")
        
        if user_id not in self.user_sessions:
            print(f"❌ No sessions found for user {user_id}")
            return []
        
        refreshed_tokens = []
        
        for session in self.user_sessions[user_id]:
            try:
                # Check if token is still valid
                validation_result = self.manager.validate_token(session["token"])
                
                # Refresh the token
                new_token = self.manager.refresh_token(
                    session["token"],
                    new_expires_in_hours=extend_hours
                )
                
                if new_token:
                    # Update session info
                    session["token"] = new_token
                    session["refreshed_at"] = datetime.now()
                    refreshed_tokens.append(new_token)
                    
                    print(f"✅ Session refreshed successfully")
                    
            except (TokenExpiredError, TokenRevokedError, InvalidTokenError) as e:
                print(f"⚠️ Skipping invalid session: {e}")
                continue
            except Exception as e:
                print(f"❌ Error refreshing session: {e}")
                continue
        
        print(f"🔄 Refreshed {len(refreshed_tokens)} sessions")
        return refreshed_tokens
    
    def security_audit(self) -> Dict[str, Any]:
        """Perform comprehensive security audit"""
        
        print(f"\n🔍 Performing security audit...")
        
        # Get current statistics
        stats = self.manager.get_stats()
        
        # Analyze active sessions
        total_sessions = sum(len(sessions) for sessions in self.user_sessions.values())
        unique_users = len(self.user_sessions)
        
        # Check for expired tokens that need cleanup
        cleanup_count = self.manager.cleanup_expired_tokens()
        
        # Role distribution
        role_distribution = {}
        for sessions in self.user_sessions.values():
            for session in sessions:
                role = session.get("role", "unknown")
                role_distribution[role] = role_distribution.get(role, 0) + 1
        
        # Permission analysis
        all_permissions = set()
        for role_perms in self.user_roles.values():
            all_permissions.update(role_perms)
        
        audit_result = {
            "timestamp": datetime.now().isoformat(),
            "token_statistics": stats,
            "session_analysis": {
                "total_sessions": total_sessions,
                "unique_users": unique_users,
                "role_distribution": role_distribution
            },
            "cleanup_performed": cleanup_count,
            "available_permissions": list(all_permissions),
            "system_health": {
                "active_tokens_ratio": stats["currently_active"] / max(stats["total_generated"], 1),
                "cleanup_needed": stats["cleanup_needed"] == 0
            }
        }
        
        print(f"✅ Security audit completed")
        print(f"   Total sessions: {total_sessions}")
        print(f"   Unique users: {unique_users}")
        print(f"   Cleaned up: {cleanup_count} expired tokens")
        print(f"   Role distribution: {role_distribution}")
        
        return audit_result
    
    def performance_test(self, num_tokens: int = 100) -> Dict[str, float]:
        """Test token generation and validation performance"""
        
        print(f"\n⚡ Performance testing with {num_tokens} tokens...")
        
        # Test token generation
        start_time = time.time()
        test_tokens = []
        
        for i in range(num_tokens):
            token = self.manager.generate_token(
                user_id=f"test_user_{i}",
                permissions=["read", "write"],
                expires_in_hours=1
            )
            test_tokens.append(token)
        
        generation_time = time.time() - start_time
        generation_per_second = num_tokens / generation_time
        
        # Test token validation
        start_time = time.time()
        
        for token in test_tokens:
            self.manager.validate_token(token)
        
        validation_time = time.time() - start_time
        validation_per_second = num_tokens / validation_time
        
        # Test batch revocation
        start_time = time.time()
        revoked_count = 0
        
        for i in range(0, num_tokens, 10):  # Revoke every 10th user's tokens
            revoked_count += self.manager.revoke_user_tokens(f"test_user_{i}")
        
        revocation_time = time.time() - start_time
        
        results = {
            "tokens_tested": num_tokens,
            "generation_time": generation_time,
            "generation_per_second": generation_per_second,
            "validation_time": validation_time,
            "validation_per_second": validation_per_second,
            "revocation_time": revocation_time,
            "tokens_revoked": revoked_count
        }
        
        print(f"✅ Performance test completed")
        print(f"   Generation: {generation_per_second:.2f} tokens/second")
        print(f"   Validation: {validation_per_second:.2f} tokens/second")
        print(f"   Revocation: {revoked_count} tokens in {revocation_time:.2f}s")
        
        return results
    
    def export_system_state(self, filename: str = None) -> str:
        """Export complete system state for backup"""
        
        if filename is None:
            filename = f"token_system_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        print(f"\n💾 Exporting system state to {filename}...")
        
        # Prepare export data
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "manager_config": self.manager.export_config(),
            "statistics": self.manager.get_stats(),
            "user_roles": self.user_roles,
            "active_sessions_count": {
                user_id: len(sessions) 
                for user_id, sessions in self.user_sessions.items()
            },
            "system_info": {
                "version": "1.0.0",
                "total_users": len(self.user_sessions),
                "available_roles": list(self.user_roles.keys())
            }
        }
        
        # Save to file
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            print(f"✅ System state exported successfully")
            print(f"   File: {filename}")
            print(f"   Size: {len(json.dumps(export_data))} characters")
            
            return filename
            
        except Exception as e:
            print(f"❌ Error exporting system state: {e}")
            raise


def main():
    """Advanced example demonstration"""
    
    print("=== SecureTokenManager - Advanced Example ===\n")
    
    # Initialize advanced system
    print("🚀 Initializing Advanced Token Management System...")
    system = TokenManagementSystem()
    print("✅ System initialized with custom configuration")
    
    # Create multiple user sessions
    users_data = [
        {"user_id": "admin_user", "role": "admin", "duration": 12, 
         "additional_data": {"department": "IT", "clearance_level": "high"}},
        {"user_id": "manager_alice", "role": "manager", "duration": 8,
         "additional_data": {"department": "Sales", "team_size": 15}},
        {"user_id": "editor_bob", "role": "editor", "duration": 6,
         "additional_data": {"department": "Content", "projects": ["blog", "docs"]}},
        {"user_id": "viewer_carol", "role": "viewer", "duration": 4,
         "additional_data": {"department": "Finance", "access_level": "restricted"}},
        {"user_id": "guest_dave", "role": "guest", "duration": 2,
         "additional_data": {"visitor_type": "trial", "referrer": "website"}}
    ]
    
    # Batch create sessions
    sessions = system.batch_create_users(users_data)
    
    # Test authorization scenarios
    print(f"\n🔐 Testing various authorization scenarios...")
    
    # Scenario 1: Admin accessing system configuration
    admin_token = sessions[0]["token"]
    result = system.validate_and_authorize(admin_token, "system_config")
    
    # Scenario 2: Editor trying to access admin features (should fail)
    editor_token = sessions[2]["token"]
    result = system.validate_and_authorize(editor_token, "system_config")
    
    # Scenario 3: Manager managing team
    manager_token = sessions[1]["token"]
    result = system.validate_and_authorize(manager_token, "manage_team")
    
    # Test token refresh
    print(f"\n🔄 Testing token refresh...")
    refreshed_tokens = system.refresh_user_sessions("manager_alice", extend_hours=12)
    
    # Performance testing
    performance_results = system.performance_test(num_tokens=50)
    
    # Security audit
    audit_results = system.security_audit()
    
    # Export system state
    backup_file = system.export_system_state()
    
    # Final statistics
    print(f"\n📊 Final System Statistics:")
    final_stats = system.manager.get_stats()
    print(f"   Total tokens generated: {final_stats['total_generated']}")
    print(f"   Total validations: {final_stats['total_validated']}")
    print(f"   Active sessions: {final_stats['currently_active']}")
    print(f"   System performance: {performance_results['generation_per_second']:.1f} gen/sec")
    
    print(f"\n✅ Advanced example completed successfully!")
    print(f"   Backup saved to: {backup_file}")
    print(f"   Total users managed: {len(system.user_sessions)}")
    print(f"   Roles configured: {len(system.user_roles)}")


if __name__ == "__main__":
    main()