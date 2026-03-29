import React, { useState, useEffect } from 'react'
import axios from 'axios'

const API_URL = 'http://localhost:8000'

function App() {
  const [health, setHealth] = useState(null)
  const [target, setTarget] = useState('http://testphp.vulnweb.com')
  const [scanType, setScanType] = useState('quick')
  const [scanning, setScanning] = useState(false)
  const [currentScan, setCurrentScan] = useState(null)
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [logs, setLogs] = useState([])

  useEffect(() => {
    checkHealth()
    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (currentScan?.id) {
      const interval = setInterval(() => pollScan(currentScan.id), 3000)
      return () => clearInterval(interval)
    }
  }, [currentScan])

  const checkHealth = async () => {
    try {
      const res = await axios.get(`${API_URL}/health`)
      setHealth(res.data)
      addLog('✅ System connected')
    } catch (error) {
      setHealth({ status: 'error' })
      addLog('❌ Connection failed')
    }
  }

  const startScan = async (e) => {
    e.preventDefault()
    setScanning(true)
    setVulnerabilities([])
    setLogs([])
    
    try {
      const res = await axios.post(`${API_URL}/api/scan/start`, {
        target_url: target,
        scan_type: scanType
      })
      setCurrentScan(res.data)
      addLog(`🚀 Started ${scanType} scan on ${target}`)
      addLog(`📋 Scan ID: ${res.data.scan_id}`)
    } catch (error) {
      addLog(`❌ Error: ${error.message}`)
      setScanning(false)
    }
  }

  const pollScan = async (scanId) => {
    try {
      const [scanRes, vulnRes] = await Promise.all([
        axios.get(`${API_URL}/api/scan/${scanId}`),
        axios.get(`${API_URL}/api/scan/${scanId}/vulnerabilities`)
      ])
      
      setCurrentScan(scanRes.data)
      setVulnerabilities(vulnRes.data)
      
      if (scanRes.data.status === 'completed' || scanRes.data.status === 'failed') {
        setScanning(false)
        addLog(`✅ Scan ${scanRes.data.status}`)
      }
    } catch (error) {
      console.error('Poll error:', error)
    }
  }

  const addLog = (message) => {
    const timestamp = new Date().toLocaleTimeString()
    setLogs(prev => [...prev, `[${timestamp}] ${message}`])
  }

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-300',
      high: 'bg-orange-100 text-orange-800 border-orange-300',
      medium: 'bg-blue-100 text-blue-800 border-blue-300',
      low: 'bg-green-100 text-green-800 border-green-300'
    }
    return colors[severity] || colors.low
  }

  const getSeverityBadge = (severity) => {
    const colors = {
      critical: 'bg-red-500 text-white',
      high: 'bg-orange-500 text-white',
      medium: 'bg-blue-500 text-white',
      low: 'bg-green-500 text-white'
    }
    return colors[severity] || colors.low
  }

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div className="glass" style={{ padding: '40px', borderRadius: '20px', marginBottom: '30px', textAlign: 'center' }}>
        <h1 style={{ fontSize: '56px', fontWeight: '800', marginBottom: '10px' }} className="gradient-text">
          🐛 ARES
        </h1>
        <p style={{ fontSize: '20px', color: '#666', marginBottom: '5px' }}>
          Automated Red-Teaming Evaluation System
        </p>
        <p style={{ fontSize: '14px', color: '#999' }}>
          AI-Powered Bug Hunter with Ollama, Hexstrike-AI & Burp Suite
        </p>
      </div>

      {/* Status Bar */}
      <div className="glass" style={{ padding: '20px', borderRadius: '15px', marginBottom: '30px', display: 'flex', justifyContent: 'space-around', flexWrap: 'wrap', gap: '20px' }}>
        <StatusItem label="Server" value={health?.status === 'healthy' ? '●' : '○'} color={health?.status === 'healthy' ? '#10b981' : '#ef4444'} />
        <StatusItem label="Database" value={health?.status === 'healthy' ? '●' : '○'} color={health?.status === 'healthy' ? '#10b981' : '#ef4444'} />
        <StatusItem label="Ollama AI" value={health?.ollama === 'running' ? '●' : '○'} color={health?.ollama === 'running' ? '#10b981' : '#f59e0b'} />
        <StatusItem label="Vulnerabilities" value={vulnerabilities.length} color="#667eea" />
      </div>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '30px', marginBottom: '30px' }}>
        {/* Start Scan Card */}
        <div className="glass hover-lift" style={{ padding: '30px', borderRadius: '15px' }}>
          <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#667eea', marginBottom: '20px', borderBottom: '3px solid #667eea', paddingBottom: '10px' }}>
            🎯 Start New Scan
          </h2>
          <form onSubmit={startScan}>
            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', marginBottom: '8px', fontWeight: '600', color: '#555' }}>
                Target URL
              </label>
              <input
                type="url"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required
                style={{ width: '100%', padding: '12px', border: '2px solid #e5e7eb', borderRadius: '8px', fontSize: '14px', outline: 'none' }}
                placeholder="http://testphp.vulnweb.com"
              />
            </div>
            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', marginBottom: '8px', fontWeight: '600', color: '#555' }}>
                Scan Type
              </label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                style={{ width: '100%', padding: '12px', border: '2px solid #e5e7eb', borderRadius: '8px', fontSize: '14px', outline: 'none' }}
              >
                <option value="quick">Quick Scan (3-5 min)</option>
                <option value="full">Full Scan (15-30 min)</option>
                <option value="deep">Deep Scan (1-2 hours)</option>
              </select>
            </div>
            <button
              type="submit"
              disabled={scanning}
              style={{
                width: '100%',
                padding: '14px',
                background: scanning ? '#ccc' : 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                color: 'white',
                border: 'none',
                borderRadius: '10px',
                fontSize: '16px',
                fontWeight: '600',
                cursor: scanning ? 'not-allowed' : 'pointer',
                transition: 'transform 0.2s'
              }}
            >
              {scanning ? '⏳ Scanning...' : '🚀 Start Scan'}
            </button>
          </form>
          
          {/* Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginTop: '25px' }}>
            <div style={{ background: '#f9fafb', padding: '20px', borderRadius: '10px', textAlign: 'center' }}>
              <div style={{ fontSize: '36px', fontWeight: '700', color: '#667eea' }}>{vulnerabilities.length}</div>
              <div style={{ fontSize: '12px', color: '#666', textTransform: 'uppercase', marginTop: '5px' }}>Vulnerabilities</div>
            </div>
            <div style={{ background: '#f9fafb', padding: '20px', borderRadius: '10px', textAlign: 'center' }}>
              <div style={{ fontSize: '36px', fontWeight: '700', color: '#667eea' }}>{currentScan?.urls_tested || 0}</div>
              <div style={{ fontSize: '12px', color: '#666', textTransform: 'uppercase', marginTop: '5px' }}>URLs Tested</div>
            </div>
          </div>
        </div>

        {/* Current Scan Card */}
        <div className="glass hover-lift" style={{ padding: '30px', borderRadius: '15px' }}>
          <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#667eea', marginBottom: '20px', borderBottom: '3px solid #667eea', paddingBottom: '10px' }}>
            📊 Current Scan Status
          </h2>
          {currentScan ? (
            <div style={{ lineHeight: '2' }}>
              <div><strong>Target:</strong> {currentScan.target_url}</div>
              <div><strong>Status:</strong> <span style={{ color: '#667eea', fontWeight: '600' }}>{currentScan.status}</span></div>
              <div><strong>Type:</strong> {currentScan.scan_type}</div>
              <div><strong>Started:</strong> {currentScan.started_at ? new Date(currentScan.started_at).toLocaleString() : 'Just now'}</div>
              {scanning && (
                <div style={{ marginTop: '20px', textAlign: 'center' }}>
                  <div className="animate-spin" style={{ width: '40px', height: '40px', margin: '0 auto', border: '4px solid #f3f4f6', borderTop: '4px solid #667eea', borderRadius: '50%' }}></div>
                  <p style={{ marginTop: '10px', color: '#667eea', fontWeight: '600' }}>Scanning...</p>
                </div>
              )}
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '60px 20px', color: '#9ca3af' }}>
              <div style={{ fontSize: '48px', marginBottom: '10px' }}>🔍</div>
              <p>No active scan</p>
            </div>
          )}
        </div>
      </div>

      {/* Bottom Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '30px' }}>
        {/* Vulnerabilities Card */}
        <div className="glass" style={{ padding: '30px', borderRadius: '15px' }}>
          <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#667eea', marginBottom: '20px', borderBottom: '3px solid #667eea', paddingBottom: '10px' }}>
            🔥 Vulnerabilities Found
          </h2>
          <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
            {vulnerabilities.length > 0 ? (
              vulnerabilities.map((vuln, idx) => (
                <div
                  key={idx}
                  className={`${getSeverityColor(vuln.severity)} animate-slide-in`}
                  style={{ padding: '15px', marginBottom: '12px', borderRadius: '10px', borderLeft: '4px solid' }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <strong style={{ fontSize: '16px' }}>{vuln.vulnerability_type}</strong>
                    <span className={`${getSeverityBadge(vuln.severity)}`} style={{ padding: '4px 12px', borderRadius: '12px', fontSize: '11px', fontWeight: '700', textTransform: 'uppercase' }}>
                      {vuln.severity}
                    </span>
                  </div>
                  <div style={{ fontSize: '14px', opacity: 0.8 }}>{vuln.url}</div>
                  {vuln.parameter && <div style={{ fontSize: '12px', marginTop: '4px', opacity: 0.7 }}>Param: {vuln.parameter}</div>}
                </div>
              ))
            ) : (
              <div style={{ textAlign: 'center', padding: '60px 20px', color: '#9ca3af' }}>
                <div style={{ fontSize: '48px', marginBottom: '10px' }}>🛡️</div>
                <p>No vulnerabilities yet</p>
                <p style={{ fontSize: '14px', marginTop: '5px' }}>Start a scan to begin testing</p>
              </div>
            )}
          </div>
        </div>

        {/* Logs Card */}
        <div className="glass" style={{ padding: '30px', borderRadius: '15px' }}>
          <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#667eea', marginBottom: '20px', borderBottom: '3px solid #667eea', paddingBottom: '10px' }}>
            📝 Scan Logs
          </h2>
          <div style={{ background: '#1e293b', color: '#10b981', padding: '20px', borderRadius: '10px', fontFamily: 'monospace', fontSize: '13px', maxHeight: '400px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
            {logs.length > 0 ? logs.join('\n') : 'Waiting for scan...'}
          </div>
        </div>
      </div>
    </div>
  )
}

function StatusItem({ label, value, color }) {
  return (
    <div style={{ textAlign: 'center', padding: '10px 20px' }}>
      <div style={{ fontSize: '12px', color: '#666', textTransform: 'uppercase', marginBottom: '5px' }}>
        {label}
      </div>
      <div style={{ fontSize: '28px', fontWeight: '700', color }}>
        {value}
      </div>
    </div>
  )
}

export default App
