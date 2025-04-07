document.addEventListener('DOMContentLoaded', function() {
    // Chart configuration
    const ctx = document.getElementById('traffic-chart').getContext('2d');
    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [
                {
                    label: 'NORMAL',
                    data: Array(20).fill(0),
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    borderWidth: 1,
                    tension: 0.3,
                    pointRadius: 0
                },
                {
                    label: 'ATTACK',
                    data: Array(20).fill(0),
                    borderColor: '#ff5555',
                    backgroundColor: 'rgba(255, 85, 85, 0.1)',
                    borderWidth: 1,
                    tension: 0.3,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(51, 51, 51, 0.5)'
                    },
                    ticks: {
                        color: '#a0a0a0'
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(51, 51, 51, 0.5)'
                    },
                    ticks: {
                        color: '#a0a0a0'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#e0e0e0',
                        font: {
                            family: "'Courier New', monospace"
                        }
                    }
                }
            }
        }
    });

    // Connect to WebSocket server
    const socket = io('http://localhost:5000');

    // Update UI with real data
    function updateUI(data) {
        document.getElementById('packets-value').textContent = data.total_packets;
        document.getElementById('attack-value').textContent = data.attack_packets;
        document.getElementById('sources-value').textContent = data.suspicious_sources;
        document.getElementById('last-alert').textContent = data.last_alert || 'NONE';
        
        const statusEl = document.getElementById('status-value');
        statusEl.textContent = data.status;
        if (data.status === 'ATTACK') {
            statusEl.classList.add('alert-value');
        } else {
            statusEl.classList.remove('alert-value');
        }
    }

    // Add traffic item to the list
    function addTrafficItem(packet) {
        const trafficList = document.getElementById('traffic-list');
        
        // Clear placeholder if exists
        if (trafficList.children.length === 1 && 
            trafficList.children[0].textContent.includes('ready')) {
            trafficList.innerHTML = '';
        }
        
        // Limit to 50 items
        if (trafficList.children.length >= 50) {
            trafficList.removeChild(trafficList.lastChild);
        }
        
        const item = document.createElement('div');
        item.className = 'data-item';
        item.innerHTML = `
            <span class="ip-address">${packet.src_ip}</span>
            <span>
                <span class="protocol">${packet.protocol}/${packet.length}</span>
                ${packet.is_attack ? '<span style="color: #ff5555"> ⚠</span>' : ''}
            </span>
        `;
        
        trafficList.insertBefore(item, trafficList.firstChild);
    }

    // Add source to threat list
    function addSourceItem(ip) {
        const sourcesList = document.getElementById('sources-list');
        
        // Clear placeholder if exists
        if (sourcesList.children.length === 1 && 
            sourcesList.children[0].textContent.includes('threats')) {
            sourcesList.innerHTML = '';
        }
        
        // Check if IP already exists
        let exists = false;
        for (let item of sourcesList.children) {
            if (item.textContent.includes(ip)) {
                exists = true;
                break;
            }
        }
        
        if (!exists) {
            const item = document.createElement('div');
            item.className = 'data-item';
            item.innerHTML = `
                <span class="ip-address">${ip}</span>
                <span style="color: #ff5555">THREAT</span>
            `;
            sourcesList.appendChild(item);
        }
    }

    // Add log entry
    function addLog(message, type = 'message') {
        const logsContainer = document.getElementById('system-logs');
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        
        const time = new Date();
        logEntry.innerHTML = `
            <span class="log-time">[${time.toLocaleTimeString()}]</span>
            <span class="log-${type}">${message}</span>
        `;
        
        logsContainer.appendChild(logEntry);
        logsContainer.scrollTop = logsContainer.scrollHeight;
    }

    // Socket event handlers
    socket.on('stats_update', (data) => {
        updateUI(data);
    });

    socket.on('packet', (packet) => {
        addTrafficItem(packet);
        if (packet.is_attack) {
            addSourceItem(packet.src_ip);
        }
    });

    socket.on('alert', (data) => {
        document.getElementById('alert-banner').style.display = 'block';
        document.getElementById('alert-message').textContent = data.message;
        addLog(`${data.message} - Top attacker: ${data.top_attacker}`, 'alert');
        
        // Hide alert after 10 seconds
        setTimeout(() => {
            document.getElementById('alert-banner').style.display = 'none';
        }, 10000);
    });

    socket.on('log', (data) => {
        addLog(data.message, data.type);
    });

    socket.on('connect', () => {
        addLog('Connected to detection server', 'success');
    });

    socket.on('disconnect', () => {
        addLog('Disconnected from server', 'alert');
    });

    // Button event listeners
    document.getElementById('start-btn').addEventListener('click', () => {
        socket.emit('start_monitoring');
    });

    document.getElementById('stop-btn').addEventListener('click', () => {
        socket.emit('stop_monitoring');
    });

    document.getElementById('block-btn').addEventListener('click', () => {
        const sourcesList = document.getElementById('sources-list');
        if (sourcesList.children.length > 0 && 
            !sourcesList.children[0].textContent.includes('threats')) {
            const count = sourcesList.children.length;
            socket.emit('block_sources');
            sourcesList.innerHTML = `
                <div class="data-item">
                    <span>No threats detected</span>
                </div>
            `;
            addLog(`Blocked ${count} threat sources`, 'alert');
        }
    });

    document.getElementById('clear-logs').addEventListener('click', () => {
        document.getElementById('system-logs').innerHTML = `
            <div class="log-entry">
                <span class="log-time">[SYSTEM]</span>
                <span class="log-message">Log cleared</span>
            </div>
        `;
    });
});