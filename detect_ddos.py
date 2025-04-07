import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import socket
import time
import threading
from datetime import datetime
import warnings
import numpy as np
from flask_socketio import emit

warnings.filterwarnings("ignore", category=RuntimeWarning)

MODEL_PATH = "ddos_model.pkl"
NORMALIZATION_PARAMS = {
    'Time_Delta': {'mean': 0.0, 'std': 1.0},
    'Length': {'mean': 0.0, 'std': 1.0}
}
EXPECTED_FEATURES = ['Time_Delta_Norm', 'Length_Norm', 'Source_Count', 'Protocol']
THRESHOLD = 0.5
BUFFER_SIZE = 100

class DDoSDetector:
    def __init__(self, socketio):
        self.socketio = socketio
        try:
            self.model = joblib.load(MODEL_PATH)
            print("✅ Model loaded successfully!")
            self.expected_features = list(self.model.feature_names_in_) if hasattr(self.model, 'feature_names_in_') else EXPECTED_FEATURES
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            raise

        self.packet_buffer = []
        self.is_monitoring = False
        self.stats = {
            "total_packets": 0,
            "attack_packets": 0,
            "last_alert": None,
            "current_ip": socket.gethostbyname(socket.gethostname()),
            "attack_sources": set()
        }

    def emit_stats(self):
        while self.is_monitoring:
            self.socketio.emit('stats_update', {
                'total_packets': self.stats["total_packets"],
                'attack_packets': self.stats["attack_packets"],
                'suspicious_sources': len(self.stats["attack_sources"]),
                'last_alert': self.stats["last_alert"].strftime("%Y-%m-%d %H:%M:%S") if self.stats["last_alert"] else None,
                'status': 'ATTACK' if self.stats["attack_packets"] > 0 else 'MONITORING'
            })
            time.sleep(1)

    def extract_features(self, packet):
        if not IP in packet:
            return None

        features = {
            "timestamp": datetime.now(),
            "src_ip": packet[IP].src,
            "length": len(packet),
            "Protocol": 6 if TCP in packet else 17 if UDP in packet else 0,
            "is_syn": 1 if TCP in packet and packet[TCP].flags == "S" else 0
        }
        return features

    def create_model_features(self, df):
        try:
            df['Time_Delta'] = df['timestamp'].diff().dt.total_seconds().fillna(0)
            df['Source_Count'] = df.groupby('src_ip')['src_ip'].transform('count')
            df['Time_Delta_Norm'] = (df['Time_Delta'] - NORMALIZATION_PARAMS['Time_Delta']['mean']) / NORMALIZATION_PARAMS['Time_Delta']['std']
            df['Length_Norm'] = (df['length'] - NORMALIZATION_PARAMS['Length']['mean']) / NORMALIZATION_PARAMS['Length']['std']
            return df[self.expected_features]
        except Exception as e:
            print(f"⚠️ Feature creation error: {e}")
            raise

    def analyze_traffic(self):
        if len(self.packet_buffer) >= BUFFER_SIZE:
            try:
                df = pd.DataFrame(self.packet_buffer)
                features = self.create_model_features(df)
                probabilities = self.model.predict_proba(features)[:, 1]
                predictions = (probabilities > THRESHOLD).astype(int)
                attack_count = predictions.sum()

                self.stats["total_packets"] += len(df)
                self.stats["attack_packets"] += attack_count

                if attack_count > 0:
                    self.stats["last_alert"] = datetime.now()
                    attack_sources = set(df[predictions == 1]['src_ip'].unique())
                    self.stats["attack_sources"].update(attack_sources)

                    for _, row in df[predictions == 1].iterrows():
                        self.socketio.emit('packet', {
                            'src_ip': row['src_ip'],
                            'protocol': 'TCP' if row['Protocol'] == 6 else 'UDP',
                            'length': row['length'],
                            'is_attack': True
                        })

                    top_attacker = df[predictions == 1]['src_ip'].value_counts().idxmax()
                    self.socketio.emit('alert', {
                        'message': f"DDoS Alert! {attack_count} malicious packets detected",
                        'top_attacker': top_attacker
                    })

                self.packet_buffer = []

            except Exception as e:
                print(f"⚠️ Analysis error: {e}")

    def packet_handler(self, packet):
        if self.is_monitoring:
            features = self.extract_features(packet)
            if features and features['src_ip'] != self.stats["current_ip"]:
                self.packet_buffer.append(features)
                self.socketio.emit('packet', {
                    'src_ip': features['src_ip'],
                    'protocol': 'TCP' if features['Protocol'] == 6 else 'UDP',
                    'length': features['length'],
                    'is_attack': False
                })
                if len(self.packet_buffer) >= BUFFER_SIZE:
                    self.analyze_traffic()

    def start_monitoring(self, interface=None):
        self.is_monitoring = True
        threading.Thread(
            target=lambda: sniff(prn=self.packet_handler, store=False, iface=interface)
        ).start()
        threading.Thread(target=self.emit_stats).start()

    def stop_monitoring(self):
        self.is_monitoring = False