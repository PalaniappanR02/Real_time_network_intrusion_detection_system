import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

class NIDSAnalytics:
    """Big Data analytics for NIDS alerts and traffic patterns"""
    
    def __init__(self, alert_file='alerts.jsonl'):
        self.alert_file = alert_file
        self.df = None
        
    def load_data(self):
        """Load alert data into pandas DataFrame"""
        alerts = []
        try:
            with open(self.alert_file, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line.strip())
                        alerts.append(alert)
            
            self.df = pd.DataFrame(alerts)
            if not self.df.empty:
                self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
                self.df['hour'] = self.df['timestamp'].dt.hour
                self.df['day_of_week'] = self.df['timestamp'].dt.day_name()
                
            print(f"Loaded {len(alerts)} alerts")
            return True
            
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def temporal_analysis(self):
        """Analyze temporal patterns in alerts"""
        if self.df is None or self.df.empty:
            return None
            
        temporal_stats = {
            'alerts_by_hour': self.df['hour'].value_counts().sort_index().to_dict(),
            'alerts_by_day': self.df['day_of_week'].value_counts().to_dict(),
            'alerts_over_time': self.df.groupby(self.df['timestamp'].dt.date).size().to_dict(),
            'peak_hours': self.df['hour'].value_counts().head(3).to_dict()
        }
        
        return temporal_stats
    
    def severity_analysis(self):
        """Analyze severity distribution and trends"""
        if self.df is None or self.df.empty:
            return None
            
        severity_stats = {
            'distribution': self.df['severity'].value_counts().to_dict(),
            'high_severity_sources': self.df[self.df['severity'] == 'high']['source_ip'].value_counts().head(10).to_dict}