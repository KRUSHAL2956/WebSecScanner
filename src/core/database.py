"""
Database Manager - MongoDB Implementation for Persistence
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from .logger import get_logger

logger = get_logger(__name__)

class DatabaseManager:
    """Manages MongoDB database operations for WebSec Scanner"""
    
    def __init__(self, connection_string: str = None):
        # Use provided connection string or default to environment variable
        self.connection_string = connection_string or os.getenv("MONGO_URI")
        if not self.connection_string:
             # Fallback for development if env var is missing (though it shouldn't be now)
             # self.connection_string = "mongodb+srv://..." 
             logger.warning("MONGO_URI not found in environment. Database connection may fail.")
             
        self.client = None
        self.db = None
        self.scans_collection = None
        self.connect()
        
    def connect(self):
        """Establish connection to MongoDB"""
        try:
            self.client = MongoClient(self.connection_string)
            # Verify connection
            self.client.admin.command('ping')
            
            self.db = self.client.get_database('websec_scanner')
            self.scans_collection = self.db.get_collection('scans')
            self.users_collection = self.db.get_collection('users')
            logger.info("Successfully connected to MongoDB Atlas")
            
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            
    def create_user(self, email: str, password_hash: str, name: str) -> bool:
        """Create a new user"""
        try:
            if self.users_collection.find_one({'email': email}):
                return False # User already exists
                
            user_doc = {
                'user_id': email, # Using email as ID for simplicity
                'email': email,
                'password_hash': password_hash,
                'name': name,
                'created_at': datetime.now()
            }
            self.users_collection.insert_one(user_doc)
            return True
        except Exception as e:
            logger.error(f"Database error creating user: {e}")
            return False

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        try:
            return self.users_collection.find_one({'email': email}, {'_id': 0})
        except Exception as e:
            logger.error(f"Database error getting user: {e}")
            return None
            
    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            return self.users_collection.find_one({'user_id': user_id}, {'_id': 0})
        except Exception as e:
            logger.error(f"Database error getting user: {e}")
            return None
            
    def update_user_password(self, user_id: str, new_password_hash: str) -> bool:
        """Update user password"""
        try:
            self.users_collection.update_one(
                {'user_id': user_id},
                {'$set': {'password_hash': new_password_hash}}
            )
            return True
        except Exception as e:
            logger.error(f"Database error updating password: {e}")
            return False

    def create_scan(self, scan_id: str, target_url: str, scan_types: List[str], user_id: str = None) -> bool:
        """Create a new scan record"""
        try:
            now = datetime.now().isoformat()
            scan_doc = {
                'scan_id': scan_id,
                'user_id': user_id, # Link scan to user
                'target_url': target_url,
                'status': 'starting',
                'progress': 0,
                'start_time': now,
                'scan_time': now,  # Added for template compatibility
                'scan_types': scan_types,
                'current_activity': 'Initializing assessment...',
                'vulnerabilities_count': 0,
                'risk_level': 'Unknown',
                'created_at': datetime.now()
            }
            
            self.scans_collection.insert_one(scan_doc)
            return True
        except Exception as e:
            logger.error(f"Database error creating scan: {e}")
            return False

    def update_scan_progress(self, scan_id: str, progress: int, status: str = None, 
                           current_activity: str = None, vulns_found: int = None, estimated_time: str = None) -> bool:
        """Update scan progress and status"""
        try:
            update_fields = {'progress': progress}
            
            if status:
                update_fields['status'] = status
            if current_activity:
                update_fields['current_activity'] = current_activity
            if vulns_found is not None:
                update_fields['vulnerabilities_count'] = vulns_found
            if estimated_time:
                update_fields['estimated_time'] = estimated_time
                
            self.scans_collection.update_one(
                {'scan_id': scan_id},
                {'$set': update_fields}
            )
            return True
        except Exception as e:
            logger.error(f"Database error updating scan: {e}")
            return False

    def complete_scan(self, scan_id: str, scan_data: Dict[str, Any]) -> bool:
        """Mark scan as completed with full results"""
        try:
            # Store full scan data in MongoDB
            update_data = {
                'status': 'completed',
                'progress': 100,
                'current_activity': 'Assessment Complete',
                'completed_at': datetime.now(),
                # Flatten important fields for easy querying, but also store full data
                'risk_level': scan_data.get('risk_score', {}).get('level', 'Unknown'),
                'vulnerabilities_count': scan_data.get('total_vulns', 0),
                'scan_data': scan_data # Store full detailed results
            }
            
            self.scans_collection.update_one(
                {'scan_id': scan_id},
                {'$set': update_data}
            )
            return True
        except Exception as e:
            logger.error(f"Database error completing scan: {e}")
            return False

    def fail_scan(self, scan_id: str, error_message: str) -> bool:
        """Mark scan as failed"""
        try:
            self.scans_collection.update_one(
                {'scan_id': scan_id},
                {'$set': {
                    'status': 'error',
                    'current_activity': f"Error: {error_message}",
                    'error_message': error_message
                }}
            )
            return True
        except Exception as e:
            logger.error(f"Database error failing scan: {e}")
            return False

    def _normalize_scan(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        """Helper to ensure scan object has required fields for templates"""
        if not scan:
            return scan
        if 'scan_time' not in scan:
            scan['scan_time'] = scan.get('start_time', 'Unknown')
        return scan

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan details by ID"""
        try:
            scan = self.scans_collection.find_one({'scan_id': scan_id}, {'_id': 0})
            return self._normalize_scan(scan)
        except Exception as e:
            logger.error(f"Database error getting scan: {e}")
            return None
            
    def get_recent_scans(self, limit: int = 10, user_id: str = None) -> List[Dict[str, Any]]:
        """Get recent scans, optionally filtered by user"""
        try:
            query = {}
            if user_id:
                query['user_id'] = user_id
                
            cursor = self.scans_collection.find(query, {'_id': 0}).sort('created_at', -1).limit(limit)
            return [self._normalize_scan(scan) for scan in cursor]
        except Exception as e:
            logger.error(f"Database error getting recent scans: {e}")
            return []

    def get_all_scans(self, user_id: str = None) -> List[Dict[str, Any]]:
        """Get all scans history, optionally filtered by user"""
        try:
            query = {}
            if user_id:
                query['user_id'] = user_id
                
            cursor = self.scans_collection.find(query, {'_id': 0}).sort('created_at', -1)
            return [self._normalize_scan(scan) for scan in cursor]
        except Exception as e:
            logger.error(f"Database error getting all scans: {e}")
            return []
