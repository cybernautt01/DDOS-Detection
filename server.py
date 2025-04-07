from flask import Flask
from flask_socketio import SocketIO
from detect_ddos import DDoSDetector
import threading

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

detector = DDoSDetector(socketio)

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('start_monitoring')
def start_monitoring():
    if not detector.is_monitoring:
        threading.Thread(target=detector.start_monitoring).start()
        socketio.emit('log', {'message': 'Monitoring started', 'type': 'success'})

@socketio.on('stop_monitoring')
def stop_monitoring():
    detector.stop_monitoring()
    socketio.emit('log', {'message': 'Monitoring stopped', 'type': 'info'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)