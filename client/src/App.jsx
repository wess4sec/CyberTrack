import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ClipboardCheck,
  Eye,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Menu,
  Pencil,
  Plus,
  RefreshCw,
  ScanLine,
  Search,
  Server,
  ShieldCheck,
  Trash2,
  Users,
  X,
} from 'lucide-react'
import './App.css'

const navigation = [
  { id: 'dashboard', label: 'Vue d’ensemble', group: 'SUPERVISION', icon: LayoutDashboard },
  { id: 'vulnerabilities', label: 'Vulnérabilités', group: 'EXPOSITION', icon: Bug },
  { id: 'assets', label: 'Actifs', group: 'EXPOSITION', icon: Server },
  { id: 'scans', label: 'Scans', group: 'OPÉRATIONS', icon: ScanLine },
  { id: 'remediation', label: 'Remédiation', group: 'OPÉRATIONS', icon: ClipboardCheck },
  { id: 'users', label: 'Utilisateurs', group: 'ADMINISTRATION', icon: Users },
]

const navigationGroups = navigation.reduce((groups, item) => {
  groups[item.group] = [...(groups[item.group] || []), item]
  return groups
}, {})

function roleLabel(role) {
  if (role === 'ADMIN') return 'Administrateur'
  if (role === 'SECURITY_ANALYST' || role === 'ANALYST') return 'Analyste sécurité'
  if (role === 'VIEWER') return 'Lecture seule'
  return role
}

const resources = {
  vulnerabilities: {
    title: 'Vulnérabilités',
    singular: 'vulnérabilité',
    endpoint: '/vulnerabilities',
    icon: Bug,
    sort: 'publishedAt',
    searchable: true,
    filters: [
      { name: 'severity', label: 'Toutes sévérités', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
      { name: 'status', label: 'Tous statuts', options: ['ACTIVE', 'MITIGATED', 'CLOSED'] },
      { name: 'minCvss', label: 'CVSS minimum', type: 'number', min: 0, max: 10, step: 0.1 },
      { name: 'maxCvss', label: 'CVSS maximum', type: 'number', min: 0, max: 10, step: 0.1 },
      { name: 'publishedFrom', label: 'Publié depuis', type: 'date' },
      { name: 'publishedTo', label: 'Publié jusqu’au', type: 'date' },
    ],
    sortOptions: [{ name: 'publishedAt', label: 'Date' }, { name: 'cvss', label: 'CVSS' }, { name: 'severity', label: 'Sévérité' }],
    columns: [
      { name: 'cveId', label: 'Identifiant' },
      { name: 'title', label: 'Vulnérabilité' },
      { name: 'severity', label: 'Sévérité', badge: true },
      { name: 'cvss', label: 'CVSS', score: true },
      { name: 'status', label: 'Statut', badge: true },
      { name: 'publishedAt', label: 'Publication', date: true },
    ],
    fields: [
      { name: 'cveId', label: 'Identifiant CVE', required: true },
      { name: 'title', label: 'Titre', required: true },
      { name: 'description', label: 'Description', type: 'textarea', required: true, wide: true },
      { name: 'severity', label: 'Sévérité', type: 'select', required: true, options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
      { name: 'cvss', label: 'Score CVSS', type: 'number', required: true },
      { name: 'status', label: 'Statut', type: 'select', required: true, options: ['ACTIVE', 'MITIGATED', 'CLOSED'] },
      { name: 'cweIds', label: 'CWE (séparés par des virgules)', type: 'array' },
      { name: 'affectedProducts', label: 'Produits concernés (séparés par des virgules)', type: 'array' },
      { name: 'publishedAt', label: 'Date de publication', type: 'datetime', required: true },
      { name: 'lastModifiedAt', label: 'Dernière modification', type: 'datetime', required: true },
      { name: 'source', label: 'Source', required: true },
      { name: 'references', label: 'Références URL (séparées par des virgules)', type: 'array', wide: true },
    ],
  },
  assets: {
    title: 'Actifs',
    singular: 'actif',
    endpoint: '/assets',
    icon: Server,
    sort: 'createdAt',
    searchable: true,
    sortOptions: [{ name: 'createdAt', label: 'Date de création' }, { name: 'hostname', label: 'Nom d’hôte' }, { name: 'criticality', label: 'Criticité' }],
    filters: [
      { name: 'environment', label: 'Tous environnements', options: ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'TEST'] },
      { name: 'criticality', label: 'Toutes criticités', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
      { name: 'isActive', label: 'Tous les états', options: ['true', 'false'], labels: ['Actif', 'Inactif'] },
    ],
    columns: [
      { name: 'hostname', label: 'Nom d’hôte' },
      { name: 'ipAddress', label: 'Adresse IP' },
      { name: 'operatingSystem', label: 'Système' },
      { name: 'environment', label: 'Environnement' },
      { name: 'criticality', label: 'Criticité', badge: true },
      { name: 'isActive', label: 'État', boolean: true },
    ],
    fields: [
      { name: 'hostname', label: 'Nom d’hôte', required: true },
      { name: 'ipAddress', label: 'Adresse IP', required: true },
      { name: 'assetType', label: 'Type d’actif', required: true },
      { name: 'operatingSystem', label: 'Système d’exploitation', required: true },
      { name: 'environment', label: 'Environnement', required: true },
      { name: 'criticality', label: 'Criticité', type: 'select', required: true, options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
      { name: 'owner', label: 'Responsable', required: true },
      { name: 'tags', label: 'Étiquettes (séparées par des virgules)', type: 'array', wide: true },
      { name: 'isActive', label: 'Actif', type: 'checkbox', default: true },
    ],
  },
  scans: {
    title: 'Scans',
    singular: 'scan',
    endpoint: '/scans',
    icon: ScanLine,
    sort: 'startedAt',
    searchable: true,
    sortOptions: [{ name: 'startedAt', label: 'Date de début' }, { name: 'completedAt', label: 'Date de fin' }, { name: 'status', label: 'Statut' }],
    filters: [
      { name: 'status', label: 'Tous statuts', options: ['PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'IMPORTED'] },
    ],
    columns: [
      { name: 'scanType', label: 'Type' },
      { name: 'assetId', label: 'Actif', object: 'hostname' },
      { name: 'status', label: 'Statut', badge: true },
      { name: 'scannedBy', label: 'Analyste', object: 'fullName' },
      { name: 'startedAt', label: 'Démarré le', date: true },
      { name: 'results', label: 'Constats', count: true },
    ],
    fields: [
      { name: 'assetId', label: 'Actif', type: 'reference', endpoint: '/assets', primary: 'hostname', secondary: 'ipAddress', sort: 'hostname', required: true },
      { name: 'scannedBy', label: 'Analyste', type: 'reference', endpoint: '/users/assignees', primary: 'fullName', secondary: 'department', required: true },
      { name: 'scanType', label: 'Type de scan / import', required: true },
      { name: 'status', label: 'Statut', required: true },
      { name: 'startedAt', label: 'Date de début', type: 'datetime', required: true },
      { name: 'completedAt', label: 'Date de fin', type: 'datetime' },
      { name: 'results', label: 'Résultats JSON', type: 'json', wide: true },
    ],
  },
  remediation: {
    title: 'Remédiation',
    singular: 'tâche',
    endpoint: '/remediation',
    icon: ClipboardCheck,
    sort: 'createdAt',
    searchable: true,
    sortOptions: [{ name: 'createdAt', label: 'Création' }, { name: 'dueDate', label: 'Échéance' }, { name: 'priority', label: 'Priorité' }, { name: 'status', label: 'Statut' }],
    filters: [
      { name: 'status', label: 'Tous statuts', options: ['OPEN', 'IN_PROGRESS', 'COMPLETED', 'BLOCKED'] },
      { name: 'priority', label: 'Toutes priorités', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
    ],
    columns: [
      { name: 'title', label: 'Tâche' },
      { name: 'vulnerabilityId', label: 'Vulnérabilité', object: 'cveId' },
      { name: 'assetId', label: 'Actif', object: 'hostname' },
      { name: 'assignedTo', label: 'Assigné à', object: 'fullName' },
      { name: 'priority', label: 'Priorité', badge: true },
      { name: 'status', label: 'Statut', badge: true },
      { name: 'dueDate', label: 'Échéance', date: true },
    ],
    fields: [
      { name: 'vulnerabilityId', label: 'Vulnérabilité', type: 'reference', endpoint: '/vulnerabilities', primary: 'cveId', secondary: 'title', sort: 'publishedAt', required: true },
      { name: 'assetId', label: 'Actif', type: 'reference', endpoint: '/assets', primary: 'hostname', secondary: 'ipAddress', sort: 'hostname', required: true },
      { name: 'assignedTo', label: 'Assigné à', type: 'reference', endpoint: '/users/assignees', primary: 'fullName', secondary: 'department', required: true },
      { name: 'title', label: 'Titre', required: true },
      { name: 'description', label: 'Description', type: 'textarea', required: true, wide: true },
      { name: 'priority', label: 'Priorité', type: 'select', required: true, options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
      { name: 'status', label: 'Statut', type: 'select', required: true, options: ['OPEN', 'IN_PROGRESS', 'COMPLETED', 'BLOCKED'] },
      { name: 'dueDate', label: 'Échéance', type: 'datetime', required: true },
    ],
  },
  users: {
    title: 'Utilisateurs',
    singular: 'utilisateur',
    endpoint: '/users',
    icon: Users,
    sort: 'fullName',
    searchable: true,
    sortOptions: [{ name: 'fullName', label: 'Nom' }, { name: 'email', label: 'E-mail' }, { name: 'createdAt', label: 'Date de création' }],
    filters: [
      { name: 'role', label: 'Tous les rôles', options: ['ADMIN', 'SECURITY_ANALYST', 'ANALYST', 'VIEWER'] },
      { name: 'isActive', label: 'Tous les états', options: ['true', 'false'], labels: ['Actif', 'Inactif'] },
    ],
    columns: [
      { name: 'fullName', label: 'Nom complet' },
      { name: 'email', label: 'Adresse e-mail' },
      { name: 'role', label: 'Rôle', badge: true },
      { name: 'department', label: 'Département' },
      { name: 'isActive', label: 'État', boolean: true },
    ],
    fields: [
      { name: 'fullName', label: 'Nom complet', required: true },
      { name: 'email', label: 'Adresse e-mail', type: 'email', required: true },
      { name: 'password', label: 'Mot de passe', type: 'password', requiredOnCreate: true },
      { name: 'role', label: 'Rôle', type: 'select', required: true, options: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'] },
      { name: 'department', label: 'Département', required: true },
      { name: 'isActive', label: 'Compte actif', type: 'checkbox', default: true },
    ],
  },
}

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    credentials: 'include',
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers,
    },
  })
  const body = await response.json()
  if (!response.ok) throw new Error(body.error?.message || `Erreur HTTP ${response.status}`)
  return body
}

function idOf(value) {
  return value && typeof value === 'object' ? value._id : value
}

function formatValue(value, column = {}) {
  if (value === null || value === undefined || value === '') return '—'
  if (column.object) return formatValue(value[column.object])
  if (column.count) return Array.isArray(value) ? value.length : 0
  if (column.boolean) return value ? 'Actif' : 'Inactif'
  if (column.date) return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium' }).format(new Date(value))
  if (Array.isArray(value)) return value.join(', ')
  if (typeof value === 'object') return value.hostname || value.fullName || value.title || value.cveId || value.email || '—'
  return value
}

function toInputValue(field, value) {
  if (field.type === 'checkbox') return Boolean(value)
  if (field.type === 'array') return Array.isArray(value) ? value.join(', ') : ''
  if (field.type === 'json') return JSON.stringify(value || [], null, 2)
  if (field.type === 'datetime' && value) return new Date(value).toISOString().slice(0, 16)
  if (['assetId', 'scannedBy', 'vulnerabilityId', 'assignedTo'].includes(field.name)) return idOf(value) || ''
  return value ?? ''
}

function referenceText(item, field) {
  if (!item || typeof item !== 'object') return ''
  return item[field.primary] || ''
}

function ReferenceInput({ field, value, selected, required, onChange }) {
  const [query, setQuery] = useState(() => referenceText(selected, field))
  const [options, setOptions] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(0)

  useEffect(() => {
    let active = true
    const timer = window.setTimeout(async () => {
      setLoading(true)
      setError('')
      try {
        const params = new URLSearchParams({ limit: '20' })
        if (query.trim()) params.set('q', query.trim())
        if (field.sort) {
          params.set('sort', field.sort)
          params.set('order', 'asc')
        }
        const result = await api(`${field.endpoint}?${params}`)
        if (active) setOptions(result.data)
      } catch (loadError) {
        if (active) setError(loadError.message)
      } finally {
        if (active) setLoading(false)
      }
    }, 200)

    return () => {
      active = false
      window.clearTimeout(timer)
    }
  }, [field.endpoint, field.sort, query])

  function updateQuery(event) {
    setQuery(event.target.value)
    setOpen(true)
    setActiveIndex(0)
    if (value) onChange('')
  }

  function chooseOption(option) {
    onChange(option._id)
    setQuery(option[field.primary] || '')
    setOpen(false)
  }

  return <div className="reference-input">
    <input
      id={field.name}
      role="combobox"
      aria-label={field.label}
      aria-autocomplete="list"
      aria-expanded={open}
      aria-controls={`${field.name}-options`}
      aria-activedescendant={open && options[activeIndex] ? `${field.name}-option-${activeIndex}` : undefined}
      autoComplete="off"
      required={required}
      value={query || (value && !selected ? String(value) : '')}
      placeholder={`Rechercher ${field.label.toLowerCase()}...`}
      onFocus={() => setOpen(true)}
      onChange={updateQuery}
      onKeyDown={event => {
        if (event.key === 'Escape') {
          event.stopPropagation()
          setOpen(false)
        }
        if (!open || !options.length) return
        if (event.key === 'ArrowDown') {
          event.preventDefault()
          setActiveIndex(index => (index + 1) % options.length)
        }
        if (event.key === 'ArrowUp') {
          event.preventDefault()
          setActiveIndex(index => (index - 1 + options.length) % options.length)
        }
        if (event.key === 'Enter' && options[activeIndex]) {
          event.preventDefault()
          chooseOption(options[activeIndex])
        }
      }}
    />
    {open && <div className="reference-options" id={`${field.name}-options`} role="listbox" aria-label={`Résultats : ${field.label}`}>
      {loading ? <span className="reference-message">Recherche en cours...</span> :
        error ? <span className="reference-message reference-error" role="alert">{error}</span> :
          options.length ? options.map((option, index) => <button
            type="button"
            role="option"
            id={`${field.name}-option-${index}`}
            aria-selected={String(option._id) === String(value)}
            key={option._id}
            onMouseDown={event => event.preventDefault()}
            onMouseEnter={() => setActiveIndex(index)}
            onClick={() => chooseOption(option)}
          >
            <strong>{option[field.primary] || option._id}</strong>
            <small>{option[field.secondary] || ''}{option.severity ? ` · ${option.severity}` : ''}</small>
          </button>) :
            <span className="reference-message">Aucun enregistrement trouvé.</span>}
    </div>}
  </div>
}

function Panel({ children, className = '' }) {
  return <section className={`panel ${className}`}>{children}</section>
}

function SeverityBadge({ value }) {
  const normalized = String(value || 'unknown').toLowerCase().replaceAll('_', '-')
  return <span className={`badge badge-${normalized}`}>{value || '—'}</span>
}

function Login({ onLogin, error, busy }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  function submit(event) {
    event.preventDefault()
    onLogin(email, password)
  }

  return (
    <main className="login-shell">
      <div className="login-layout">
        <section className="login-intro" aria-label="Présentation de CyberTrack">
          <div className="brand login-brand"><div className="brand-mark"><ShieldCheck size={21} /></div><span>Cyber<span>Track</span></span></div>
          <p className="eyebrow">GESTION DE L’EXPOSITION AUX VULNÉRABILITÉS</p>
          <h1>La posture de sécurité, <span>en contexte.</span></h1>
          <p className="login-description">Inventaire des actifs, suivi des vulnérabilités et coordination des actions de remédiation dans un espace opérationnel unique.</p>
          <div className="login-facts"><span><i /> Données de votre environnement</span><span><i /> Accès contrôlé par rôle</span></div>
        </section>
        <form className="login-card" onSubmit={submit}>
          <div className="login-card-heading">
            <p className="eyebrow">ACCÈS À LA PLATEFORME</p>
            <h2>Se connecter</h2>
            <p className="muted">Saisissez les identifiants de votre compte CyberTrack.</p>
          </div>
          <label htmlFor="login-email">
            Adresse e-mail
            <input id="login-email" type="email" autoComplete="username" required value={email} onChange={event => setEmail(event.target.value)} />
          </label>
          <label htmlFor="login-password">
            Mot de passe
            <input id="login-password" type="password" autoComplete="current-password" required value={password} onChange={event => setPassword(event.target.value)} />
          </label>
          {error && <p className="inline-error" role="alert">{error}</p>}
          <button className="button button-primary button-full" disabled={busy}>
            {busy ? <LoaderCircle className="spin" size={17} /> : <LockKeyhole size={17} />}
            {busy ? 'Connexion en cours…' : 'Se connecter'}
          </button>
          <p className="login-footnote">La session est gérée de manière sécurisée par le serveur.</p>
        </form>
      </div>
    </main>
  )
}

function Dashboard({ setView }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(true)

  const load = useCallback(async () => {
    setBusy(true)
    setError('')
    try {
      const [overview, severity, vulnerabilityStatus, trends, topVulnerabilities, topAssets, frequentCves, scans, tasks] = await Promise.all([
        api('/dashboard/overview'),
        api('/dashboard/severity'),
        api('/dashboard/vulnerability-status'),
        api('/dashboard/monthly-trends'),
        api('/dashboard/top-vulnerabilities'),
        api('/dashboard/top-assets'),
        api('/dashboard/frequent-cves'),
        api('/scans?limit=5&sort=startedAt&order=desc'),
        api('/remediation?limit=5&sort=createdAt&order=desc'),
      ])
      setData({
        overview: overview.data,
        severity: severity.data,
        vulnerabilityStatus: vulnerabilityStatus.data,
        trends: trends.data.slice(-8),
        vulnerabilities: topVulnerabilities.data.slice(0, 5),
        topAssets: topAssets.data,
        frequentCves: frequentCves.data,
        scans: scans.data,
        tasks: tasks.data,
      })
    } catch (loadError) {
      setError(loadError.message)
    } finally {
      setBusy(false)
    }
  }, [])

  useEffect(() => {
    const timer = window.setTimeout(() => { void load() }, 0)
    return () => window.clearTimeout(timer)
  }, [load])

  if (busy) return <div className="loading-state"><LoaderCircle className="spin" /> Chargement des indicateurs...</div>
  if (error) return <ErrorState message={error} retry={load} />
  if (!data) return null

  const severityMap = Object.fromEntries(data.severity.map(item => [item.severity, item.count]))
  const maxStatus = Math.max(1, ...data.vulnerabilityStatus.map(item => item.count))
  const metrics = [
    { label: 'Vulnérabilités', value: data.overview.totalVulnerabilities },
    { label: 'Critiques', value: severityMap.CRITICAL || 0, emphasis: 'critical' },
    { label: 'Actifs surveillés', value: data.overview.activeAssets },
    { label: 'Tâches ouvertes', value: data.overview.openRemediationTasks },
    { label: 'En retard', value: data.overview.overdueRemediationTasks, emphasis: 'critical' },
    { label: 'Scans enregistrés', value: data.overview.totalScans },
  ]
  const maxSeverity = Math.max(1, ...data.severity.map(item => item.count))
  const completedRecentTasks = data.tasks.filter(task => task.status === 'COMPLETED').length
  const recentTaskProgress = data.tasks.length ? Math.round((completedRecentTasks / data.tasks.length) * 100) : 0

  return (
    <div className="dashboard-page">
      <div className="page-heading">
        <div><p className="eyebrow">CENTRE DES OPÉRATIONS DE SÉCURITÉ</p><h1>Vue d’ensemble</h1><p className="muted">Indicateurs calculés à partir des actifs, vulnérabilités, scans et tâches enregistrés.</p></div>
        <button className="button button-secondary" onClick={() => void load()}><RefreshCw size={15} /> Actualiser</button>
      </div>
      <div className="metric-strip" aria-label="Indicateurs clés">
        {metrics.map(metric => <div className={`metric-item ${metric.emphasis || ''}`} key={metric.label}>
          <span>{metric.label}</span><strong>{Number(metric.value || 0).toLocaleString('fr-FR')}</strong>
        </div>)}
      </div>
      <div className="dashboard-grid">
        <Panel className="dashboard-panel">
          <div className="panel-heading"><div><h2>Exposition par sévérité</h2><p className="muted">Vulnérabilités présentes dans l’inventaire</p></div><span className="panel-total">{Number(data.overview.totalVulnerabilities || 0).toLocaleString('fr-FR')}</span></div>
          {data.severity.length ? <div className="severity-chart">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(level => {
              const count = severityMap[level] || 0
              return <div className="severity-row" key={level}><span><SeverityBadge value={level} /></span><div className="bar-track"><i className={`bar-${level.toLowerCase()}`} style={{ width: `${(count / maxSeverity) * 100}%` }} /></div><strong>{count.toLocaleString('fr-FR')}</strong></div>
            })}
          </div> : <p className="empty-note">Aucune vulnérabilité enregistrée.</p>}
        </Panel>
        <Panel className="dashboard-panel">
          <div className="panel-heading"><div><h2>Exposition des actifs</h2><p className="muted">Actifs les plus concernés selon les constats enregistrés</p></div><button className="text-button" onClick={() => setView('assets')}>Inventaire <ChevronRight size={14} /></button></div>
          <RankedList rows={data.topAssets} primary="hostname" secondary="ipAddress" metric="findingCount" metricLabel="constats" empty="Aucun constat associé à un actif." />
        </Panel>
        <Panel className="dashboard-panel">
          <div className="panel-heading"><div><h2>Cycle de traitement</h2><p className="muted">Répartition selon le statut enregistré</p></div><button className="text-button" onClick={() => setView('vulnerabilities')}>Inventaire <ChevronRight size={14} /></button></div>
          {data.vulnerabilityStatus.length ? <div className="severity-chart">
            {data.vulnerabilityStatus.map(item => <div className="severity-row status-row" key={item.status}><span><SeverityBadge value={item.status} /></span><div className="bar-track"><i className={`bar-status-${String(item.status).toLowerCase()}`} style={{ width: `${(item.count / maxStatus) * 100}%` }} /></div><strong>{item.count.toLocaleString('fr-FR')}</strong></div>)}
          </div> : <p className="empty-note">Aucun statut de vulnérabilité disponible.</p>}
        </Panel>
        <Panel className="dashboard-panel dashboard-wide">
          <div className="panel-heading"><div><h2>Évolution des publications</h2><p className="muted">Nombre de vulnérabilités par mois, regroupées selon leur date de publication</p></div><span className="chart-legend"><i /> Vulnérabilités</span></div>
          <TrendChart rows={data.trends} />
        </Panel>
        <Panel className="dashboard-panel dashboard-wide">
          <div className="panel-heading"><div><h2>À examiner en priorité</h2><p className="muted">Cinq scores CVSS les plus élevés retournés par l’API</p></div><button className="text-button" onClick={() => setView('vulnerabilities')}>Voir l’inventaire <ChevronRight size={14} /></button></div>
          <DataTable
            columns={resources.vulnerabilities.columns.slice(0, 5)}
            rows={data.vulnerabilities}
            onSelect={() => setView('vulnerabilities')}
            emptyMessage="Aucune vulnérabilité à afficher."
          />
        </Panel>
        <Panel className="dashboard-panel">
          <div className="panel-heading"><div><h2>Progression des remédiations</h2><p className="muted">État des tâches récentes chargées</p></div><button className="text-button" onClick={() => setView('remediation')}>Ouvrir <ChevronRight size={14} /></button></div>
          {data.tasks.length ? <div className="remediation-progress">
            <div className="progress-summary"><strong>{completedRecentTasks} <span>/ {data.tasks.length}</span></strong><span>terminée{completedRecentTasks > 1 ? 's' : ''}</span></div>
            <div className="progress-track" role="progressbar" aria-label="Tâches récentes terminées" aria-valuemin="0" aria-valuemax={data.tasks.length} aria-valuenow={completedRecentTasks}><i style={{ width: `${recentTaskProgress}%` }} /></div>
            <p className="muted">Calculée sur les {data.tasks.length} tâche{data.tasks.length > 1 ? 's' : ''} récentes renvoyées par l’API.</p>
          </div> : <p className="empty-note">Aucune tâche récente enregistrée.</p>}
        </Panel>
        <Panel className="dashboard-panel">
          <div className="panel-heading"><div><h2>CVE les plus fréquentes</h2><p className="muted">Occurrences dans les scans enregistrés</p></div></div>
          <RankedList rows={data.frequentCves} primary="cveId" secondary="title" metric="occurrenceCount" metricLabel="occurrences" empty="Aucun résultat de scan." />
        </Panel>
        <Panel className="dashboard-panel dashboard-wide">
          <div className="panel-heading"><div><h2>Activité récente</h2><p className="muted">Scans et tâches de remédiation enregistrés</p></div></div>
          <RecentActivity scans={data.scans} tasks={data.tasks} setView={setView} />
        </Panel>
      </div>
    </div>
  )
}

function TrendChart({ rows }) {
  if (!rows.length) return <p className="empty-note">Aucune tendance mensuelle disponible.</p>
  const width = 720
  const height = 190
  const insetX = 20
  const insetY = 18
  const maximum = Math.max(1, ...rows.map(row => row.count))
  const points = rows.map((row, index) => {
    const x = rows.length === 1 ? width / 2 : insetX + index * (width - insetX * 2) / (rows.length - 1)
    const y = height - insetY - (row.count / maximum) * (height - insetY * 2)
    return { x, y, row }
  })
  const line = points.map((point, index) => `${index ? 'L' : 'M'} ${point.x} ${point.y}`).join(' ')

  return <div className="trend-chart">
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Tendance mensuelle des vulnérabilités publiées : ${rows.map(row => `${row.count} en ${row.month}/${row.year}`).join(', ')}`}>
      {[0, 1, 2, 3].map(step => {
        const y = insetY + step * (height - insetY * 2) / 3
        return <line className="trend-gridline" key={step} x1={insetX} y1={y} x2={width - insetX} y2={y} />
      })}
      <path className="trend-line" d={line} />
      {points.map(({ x, y, row }) => <circle className="trend-point" key={`${row.year}-${row.month}`} cx={x} cy={y} r="3.5">
        <title>{`${row.count} vulnérabilités — ${new Intl.DateTimeFormat('fr-FR', { month: 'long', year: 'numeric' }).format(new Date(row.year, row.month - 1))}`}</title>
      </circle>)}
    </svg>
    <div className="trend-labels">{points.map(({ x, row }) => <span key={`${row.year}-${row.month}`} style={{ left: `${(x / width) * 100}%` }}>{new Intl.DateTimeFormat('fr-FR', { month: 'short' }).format(new Date(row.year, row.month - 1))} {String(row.year).slice(-2)}</span>)}</div>
  </div>
}

function RankedList({ rows, primary, secondary, metric, metricLabel, empty }) {
  if (!rows.length) return <p className="empty-note">{empty}</p>
  return <div className="recent-list">{rows.slice(0, 5).map(row => (
    <div className="recent-item" key={row._id || row.cveId || row.hostname}>
      <span className="rank-number">{row[metric].toLocaleString('fr-FR')}</span>
      <div className="recent-copy"><strong>{row[primary]}</strong><small>{row[secondary]}</small></div>
      <span className="rank-label">{metricLabel}</span>
    </div>
  ))}</div>
}

function RecentActivity({ scans, tasks, setView }) {
  const events = [
    ...scans.map(row => ({ id: `scan-${row._id}`, kind: 'scans', label: 'Scan', title: formatValue(row.assetId), detail: row.scanType, status: row.status, date: row.startedAt })),
    ...tasks.map(row => ({ id: `task-${row._id}`, kind: 'remediation', label: 'Remédiation', title: row.title, detail: formatValue(row.assignedTo), status: row.status, date: row.createdAt })),
  ].filter(event => event.date && !Number.isNaN(new Date(event.date).getTime()))
    .sort((left, right) => new Date(right.date) - new Date(left.date))
    .slice(0, 6)

  if (!events.length) return <p className="empty-note">Aucun scan ou tâche récent à afficher.</p>
  return <div className="activity-list">{events.map(event => <button className="activity-row" key={event.id} onClick={() => setView(event.kind)}>
    <span className={`activity-kind ${event.kind}`}>{event.kind === 'scans' ? <ScanLine size={14} /> : <ClipboardCheck size={14} />}</span>
    <span className="activity-copy"><strong>{event.title}</strong><small>{event.label} · {event.detail || '—'}</small></span>
    <SeverityBadge value={event.status} />
    <time dateTime={new Date(event.date).toISOString()}>{new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium' }).format(new Date(event.date))}</time>
  </button>)}</div>
}

function DataTable({ columns, rows, onSelect, onEdit, onDelete, canEdit, emptyMessage = 'Aucun résultat pour ces critères.' }) {
  if (!rows.length) return <div className="empty-table"><strong>{emptyMessage}</strong><span>Ajustez la recherche ou les filtres, ou créez un enregistrement.</span></div>
  return <div className="table-scroll"><table><thead><tr>{columns.map(column => <th key={column.name}>{column.label}</th>)}<th className="actions-heading">Actions</th></tr></thead>
    <tbody>{rows.map(row => <tr key={row._id}>
      {columns.map(column => <td key={column.name}>
        {column.badge ? <SeverityBadge value={formatValue(row[column.name], column)} /> :
          column.score ? <span className={`score score-${String(row[column.name]).split('.')[0]}`}>{formatValue(row[column.name])}</span> :
            <span className={column.name === 'title' ? 'cell-title' : ''}>{formatValue(row[column.name], column)}</span>}
      </td>)}
      <td><div className="row-actions">
        {onSelect && <button className="icon-button" title="Détails" aria-label="Détails" onClick={() => onSelect(row)}><Eye size={16} /></button>}
        {canEdit && <button className="icon-button" title="Modifier" aria-label="Modifier" onClick={() => onEdit(row)}><Pencil size={15} /></button>}
        {canEdit && <button className="icon-button danger-action" title="Supprimer" aria-label="Supprimer" onClick={() => onDelete(row)}><Trash2 size={15} /></button>}
      </div></td>
    </tr>)}</tbody>
  </table></div>
}

function ResourcePage({ view, currentUser }) {
  const config = resources[view]
  const canEdit = currentUser.role === 'ADMIN' || currentUser.role === 'SECURITY_ANALYST' || currentUser.role === 'ANALYST'
  const [rows, setRows] = useState([])
  const [pagination, setPagination] = useState({ page: 1, pages: 0, total: 0, limit: 20 })
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [filters, setFilters] = useState({})
  const [sort, setSort] = useState(config.sort)
  const [order, setOrder] = useState('desc')
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [dialog, setDialog] = useState(null)
  const [saving, setSaving] = useState(false)
  const [limit, setLimit] = useState(20)
  const [notice, setNotice] = useState('')

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(search.trim()), 300)
    return () => window.clearTimeout(timer)
  }, [search])

  const load = useCallback(async () => {
    setBusy(true)
    setError('')
    try {
      const params = new URLSearchParams({ page: String(page), limit: String(limit), sort, order })
      if (config.searchable && debouncedSearch) params.set('q', debouncedSearch)
      Object.entries(filters).forEach(([key, value]) => { if (value) params.set(key, value) })
      const result = await api(`${config.endpoint}?${params}`)
      setRows(result.data)
      setPagination(result.pagination)
    } catch (loadError) {
      setError(loadError.message)
    } finally {
      setBusy(false)
    }
  }, [config, page, limit, debouncedSearch, filters, sort, order])

  useEffect(() => {
    const timer = window.setTimeout(() => { void load() }, 0)
    return () => window.clearTimeout(timer)
  }, [load])

  function openForm(row) {
    setDialog({ mode: row ? 'edit' : 'create', row })
  }

  async function save(formValues) {
    setSaving(true)
    setError('')
    try {
      const payload = {}
      config.fields.forEach(field => {
        let value = formValues[field.name]
        if (field.type === 'checkbox') value = Boolean(value)
        else if (field.type === 'array') value = value.split(',').map(item => item.trim()).filter(Boolean)
        else if (field.type === 'number' && value !== '') value = Number(value)
        else if (field.type === 'json') {
          try { value = JSON.parse(value || '[]') } catch { throw new Error(`Le champ « ${field.label} » doit contenir un JSON valide.`) }
        }
        if (value === '' && !field.required && !field.requiredOnCreate) return
        if (field.type === 'password' && !value) return
        payload[field.name] = value
      })
      const editing = dialog.mode === 'edit'
      await api(editing ? `${config.endpoint}/${dialog.row._id}` : config.endpoint, {
        method: editing ? 'PUT' : 'POST',
        body: JSON.stringify(payload),
      })
      setDialog(null)
      await load()
      setNotice(editing ? 'Modifications enregistrées.' : 'Enregistrement créé.')
    } catch (saveError) {
      setError(saveError.message)
    } finally {
      setSaving(false)
    }
  }

  async function remove(row) {
    if (!window.confirm(`Supprimer cet élément (« ${row[config.columns[0].name]} ») ?`)) return
    try {
      await api(`${config.endpoint}/${row._id}`, { method: 'DELETE' })
      await load()
      setNotice('Enregistrement supprimé.')
    } catch (deleteError) {
      setError(deleteError.message)
    }
  }

  return <div className="resource-page">
    <div className="page-heading">
      <div><p className="eyebrow">{config.endpoint === '/users' ? 'CONTRÔLE DES ACCÈS' : 'INVENTAIRE ET OPÉRATIONS'}</p><h1>{config.title}</h1><p className="muted">{pagination.total.toLocaleString('fr-FR')} élément{pagination.total > 1 ? 's' : ''} dans votre environnement.</p></div>
      {canEdit && <button className="button button-primary" onClick={() => openForm()}><Plus size={17} /> Nouvelle {config.singular}</button>}
    </div>
    <Panel className="resource-panel">
      <div className="filter-toolbar">
        <div className="toolbar-search">
          <Search size={17} />
          <input aria-label="Rechercher" placeholder={config.searchable ? 'Rechercher...' : `Filtrer ${config.title.toLowerCase()}...`} value={search} onChange={event => { setBusy(true); setPage(1); setSearch(event.target.value) }} />
        </div>
        {config.filters.map(filter => filter.type ? <input
          aria-label={filter.label}
          className="filter-input"
          key={filter.name}
          type={filter.type}
          min={filter.min}
          max={filter.max}
          step={filter.step}
          placeholder={filter.label}
          value={filters[filter.name] || ''}
          onChange={event => { setBusy(true); setPage(1); setFilters(current => ({ ...current, [filter.name]: event.target.value })) }}
        /> : <select aria-label={filter.label} key={filter.name} value={filters[filter.name] || ''} onChange={event => { setBusy(true); setPage(1); setFilters(current => ({ ...current, [filter.name]: event.target.value })) }}>
          <option value="">{filter.label}</option>
          {filter.options.map((option, index) => <option value={option} key={option}>{filter.labels?.[index] || option.replaceAll('_', ' ')}</option>)}
        </select>)}
        {config.sortOptions && <select aria-label="Trier par" value={sort} onChange={event => { setBusy(true); setPage(1); setSort(event.target.value) }}>
          {config.sortOptions.map(option => <option value={option.name} key={option.name}>Tri : {option.label}</option>)}
        </select>}
        {config.sortOptions && <select aria-label="Ordre de tri" value={order} onChange={event => { setBusy(true); setPage(1); setOrder(event.target.value) }}><option value="desc">Décroissant</option><option value="asc">Croissant</option></select>}
        <button className="icon-button refresh-button" title="Actualiser" aria-label="Actualiser" onClick={() => { setBusy(true); void load() }}><RefreshCw size={16} /></button>
      </div>
      {error && <div className="error-banner" role="alert"><AlertTriangle size={17} />{error}<button onClick={() => setError('')} aria-label="Fermer"><X size={15} /></button></div>}
      {notice && <div className="success-banner" role="status"><CheckCircle2 size={16} />{notice}<button onClick={() => setNotice('')} aria-label="Fermer"><X size={15} /></button></div>}
      {busy ? <div className="loading-state"><LoaderCircle className="spin" /> Chargement des données...</div> :
        <DataTable columns={config.columns} rows={rows} onSelect={row => setDialog({ mode: 'detail', row })} onEdit={openForm} onDelete={remove} canEdit={canEdit} />}
      <div className="table-footer">
        <span>{pagination.total ? `${((page - 1) * pagination.limit) + 1}–${Math.min(page * pagination.limit, pagination.total)} sur ${pagination.total}` : 'Aucun résultat'}</span>
        <div className="pagination-controls">
          <button className="icon-button" disabled={page <= 1} onClick={() => { setBusy(true); setPage(current => current - 1) }} aria-label="Page précédente"><ChevronLeft size={17} /></button>
          <span>Page {page} / {Math.max(pagination.pages, 1)}</span>
          <button className="icon-button" disabled={page >= pagination.pages} onClick={() => { setBusy(true); setPage(current => current + 1) }} aria-label="Page suivante"><ChevronRight size={17} /></button>
          <select aria-label="Taille de page" value={limit} onChange={event => { setBusy(true); setPage(1); setLimit(Number(event.target.value)) }}><option value="10">10</option><option value="20">20</option><option value="50">50</option><option value="100">100</option></select>
        </div>
      </div>
    </Panel>
    {dialog?.mode === 'detail' && <DetailDialog key={dialog.row._id} row={dialog.row} config={config} onClose={() => setDialog(null)} />}
    {(dialog?.mode === 'edit' || dialog?.mode === 'create') && <ResourceForm key={`${view}-${dialog.mode}-${dialog.row?._id || 'new'}`} config={config} row={dialog.row} busy={saving} onClose={() => setDialog(null)} onSave={save} />}
  </div>
}

function ResourceForm({ config, row, busy, onClose, onSave }) {
  const initial = useMemo(() => Object.fromEntries(config.fields.map(field => [field.name, toInputValue(field, row?.[field.name] ?? field.default)])), [config, row])
  const [values, setValues] = useState(initial)
  const [error, setError] = useState('')
  const editing = Boolean(row)

  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === 'Escape' && !busy) onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [busy, onClose])

  function submit(event) {
    event.preventDefault()
    const missing = config.fields.find(field => (field.required || (!editing && field.requiredOnCreate)) && !values[field.name])
    if (missing) {
      setError(`Le champ « ${missing.label} » est obligatoire.`)
      return
    }
    onSave(values)
  }

  return <div className="modal-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onClose() }}>
    <section className="modal-card form-modal" role="dialog" aria-modal="true" aria-labelledby="form-title">
      <div className="modal-heading"><div><p className="eyebrow">{editing ? 'MODIFICATION' : 'NOUVEL ENREGISTREMENT'}</p><h2 id="form-title">{editing ? 'Modifier' : 'Créer'} {config.singular}</h2></div><button className="icon-button" onClick={onClose} aria-label="Fermer" autoFocus><X size={18} /></button></div>
      <form onSubmit={submit}>
        <div className="form-grid">{config.fields.map(field => {
          const fieldRequired = field.required || (!editing && field.requiredOnCreate)
          const common = {
            id: field.name,
            required: fieldRequired,
            value: values[field.name] ?? '',
            onChange: event => setValues(current => ({ ...current, [field.name]: event.target.type === 'checkbox' ? event.target.checked : event.target.value })),
          }
          if (field.type === 'checkbox') return <label className="checkbox-field" key={field.name}><input {...common} type="checkbox" /><span>{field.label}</span></label>
          return <label className={field.wide ? 'wide-field' : ''} key={field.name} htmlFor={field.name}>{field.label}
            {field.type === 'reference' ? <ReferenceInput field={field} value={values[field.name]} selected={row?.[field.name]} required={fieldRequired} onChange={value => setValues(current => ({ ...current, [field.name]: value }))} /> :
              field.type === 'select' ? <select {...common}><option value="">Sélectionner...</option>{field.options.map(option => <option key={option} value={option}>{option.replaceAll('_', ' ')}</option>)}</select> :
              field.type === 'textarea' || field.type === 'json' ? <textarea {...common} rows={field.type === 'json' ? 7 : 4} /> :
                <input {...common} type={field.type === 'datetime' ? 'datetime-local' : field.type || 'text'} step={field.type === 'number' ? '0.1' : undefined} />}
          </label>
        })}</div>
        {error && <p className="inline-error" role="alert">{error}</p>}
        <div className="modal-actions"><button type="button" className="button button-quiet" onClick={onClose}>Annuler</button><button className="button button-primary" disabled={busy}>{busy && <LoaderCircle className="spin" size={16} />}{editing ? 'Enregistrer' : 'Créer'}</button></div>
      </form>
    </section>
  </div>
}

function DetailDialog({ row, config, onClose }) {
  const relatedSupported = config.endpoint === '/assets' || config.endpoint === '/vulnerabilities'
  const [related, setRelated] = useState(null)
  const [relatedError, setRelatedError] = useState('')
  const [relatedBusy, setRelatedBusy] = useState(relatedSupported)

  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  useEffect(() => {
    if (!relatedSupported) return undefined
    let active = true
    api(`${config.endpoint}/${row._id}/related`).then(result => {
      if (active) setRelated(result.data)
    }).catch(error => {
      if (active) setRelatedError(error.message)
    }).finally(() => {
      if (active) setRelatedBusy(false)
    })
    return () => { active = false }
  }, [config.endpoint, relatedSupported, row._id])

  const relatedGroups = related ? config.endpoint === '/assets'
    ? [
      { title: 'Vulnérabilités associées', rows: related.vulnerabilities, primary: 'cveId', secondary: 'title', meta: 'findingCount', metaLabel: 'constats' },
      { title: 'Scans associés', rows: related.scans, primary: 'scanType', secondary: 'status', meta: 'startedAt', date: true },
      { title: 'Tâches de remédiation', rows: related.remediationTasks, primary: 'title', secondary: 'assignedTo', nested: 'fullName', meta: 'status' },
    ]
    : [
      { title: 'Assets concernés', rows: related.assets, primary: 'hostname', secondary: 'ipAddress', meta: 'remediationTaskCount', metaLabel: 'tâches' },
      { title: 'Scans associés', rows: related.scans, primary: 'scanType', secondary: 'assetId', nested: 'hostname', meta: 'status' },
      { title: 'Tâches de remédiation', rows: related.remediationTasks, primary: 'title', secondary: 'assignedTo', nested: 'fullName', meta: 'status' },
    ] : []

  return <div className="modal-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onClose() }}>
    <section className="modal-card detail-modal" role="dialog" aria-modal="true" aria-labelledby="detail-title">
      <div className="modal-heading"><div><p className="eyebrow">FICHE DÉTAILLÉE</p><h2 id="detail-title">{row.title || row.cveId || row.hostname || row.fullName || config.singular}</h2></div><button className="icon-button" onClick={onClose} aria-label="Fermer" autoFocus><X size={18} /></button></div>
      <dl className="detail-grid">{Object.entries(row).filter(([key]) => key !== '_id').map(([key, value]) => <div key={key} className={key === 'description' || key === 'history' || key === 'results' || key === 'references' ? 'detail-wide' : ''}><dt>{key.replaceAll(/([A-Z])/g, ' $1').replace(/^./, letter => letter.toUpperCase())}</dt><dd>{Array.isArray(value) || (value && typeof value === 'object') ? <pre>{JSON.stringify(value, null, 2)}</pre> : formatValue(value)}</dd></div>)}</dl>
      {relatedSupported && <section className="related-section">
        <div className="related-heading"><h3>Relations dans l’inventaire</h3><span>Calculées depuis les scans et tâches enregistrés</span></div>
        {relatedBusy ? <p className="empty-note">Chargement des relations...</p> :
          relatedError ? <p className="inline-error" role="alert">{relatedError}</p> :
            <div className="related-grid">{relatedGroups.map(group => <RelatedGroup key={group.title} {...group} />)}</div>}
      </section>}
    </section>
  </div>
}

function RelatedGroup({ title, rows, primary, secondary, nested, meta, metaLabel, date }) {
  return <section className="related-group">
    <h4>{title}<span>{rows.length}</span></h4>
    {!rows.length ? <p className="empty-note">Aucune relation enregistrée.</p> :
      <ul>{rows.slice(0, 8).map((row, index) => {
        const secondaryValue = nested ? row[secondary]?.[nested] : row[secondary]
        const metaValue = date && row[meta] ? new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium' }).format(new Date(row[meta])) : row[meta]
        return <li key={row._id || `${primary}-${index}`}><div><strong>{formatValue(row[primary])}</strong><small>{formatValue(secondaryValue)}</small></div><span>{metaLabel ? `${row[meta] || 0} ${metaLabel}` : formatValue(metaValue)}</span></li>
      })}</ul>}
  </section>
}

function ErrorState({ message, retry }) {
  return <div className="error-state"><AlertTriangle size={22} /><strong>Impossible de charger les données.</strong><p>{message}</p><button className="button button-quiet" onClick={retry}><RefreshCw size={15} /> Réessayer</button></div>
}

function App() {
  const [currentUser, setCurrentUser] = useState(null)
  const [authLoading, setAuthLoading] = useState(true)
  const [authError, setAuthError] = useState('')
  const [authBusy, setAuthBusy] = useState(false)
  const [healthStatus, setHealthStatus] = useState('checking')
  const [view, setView] = useState('dashboard')
  const [sidebarOpen, setSidebarOpen] = useState(false)

  useEffect(() => {
    function closeSidebar(event) {
      if (event.key === 'Escape') setSidebarOpen(false)
    }
    window.addEventListener('keydown', closeSidebar)
    return () => window.removeEventListener('keydown', closeSidebar)
  }, [])

  useEffect(() => {
    api('/auth/me').then(result => setCurrentUser(result.data.user)).catch(error => {
      if (!error.message.includes('Authentication')) setAuthError('Le serveur API est injoignable. Vérifiez que le backend est démarré.')
    }).finally(() => setAuthLoading(false))
  }, [])

  useEffect(() => {
    let active = true
    const checkHealth = async () => {
      try {
        const result = await api('/health')
        if (active) setHealthStatus(result.data.database === 'connected' ? 'connected' : 'unavailable')
      } catch {
        if (active) setHealthStatus('unavailable')
      }
    }
    void checkHealth()
    const timer = window.setInterval(checkHealth, 30000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])

  async function login(email, password) {
    setAuthBusy(true)
    setAuthError('')
    try {
      const result = await api('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })
      setCurrentUser(result.data.user)
    } catch (error) {
      setAuthError(error.message)
    } finally {
      setAuthBusy(false)
    }
  }

  async function logout() {
    try {
      await api('/auth/logout', { method: 'POST' })
      setCurrentUser(null)
      setView('dashboard')
    } catch (error) {
      setAuthError(error.message)
    }
  }

  if (authLoading) return <div className="boot-state"><LoaderCircle className="spin" size={24} /><span>Connexion à CyberTrack...</span></div>
  if (!currentUser) return <Login onLogin={login} error={authError} busy={authBusy} />

  const activeItem = navigation.find(item => item.id === view) || navigation[0]
  return <div className="app-shell">
    <aside className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><ShieldCheck size={19} /></div><span>Cyber<span>Track</span></span><button className="icon-button sidebar-close" onClick={() => setSidebarOpen(false)} aria-label="Fermer le menu"><X size={18} /></button></div>
      <div className="workspace-switch"><span className="workspace-monogram">CT</span><span><strong>Centre de sécurité</strong><small>Environnement actif</small></span><ChevronRight size={14} /></div>
      <nav aria-label="Navigation principale">{Object.entries(navigationGroups).map(([group, items]) => {
        const visibleItems = items.filter(item => item.id !== 'users' || currentUser.role === 'ADMIN')
        if (!visibleItems.length) return null
        return <div className="nav-group" key={group}>
          <p className="nav-caption">{group}</p>
          {visibleItems.map(item => {
            const Icon = item.icon
            return <button key={item.id} className={`nav-link ${view === item.id ? 'nav-active' : ''}`} aria-current={view === item.id ? 'page' : undefined} onClick={() => { setView(item.id); setSidebarOpen(false) }}><Icon size={16} /><span>{item.label}</span></button>
          })}
        </div>
      })}</nav>
      <div className="sidebar-bottom"><div className="security-status"><span className={`status-pulse ${healthStatus}`} /><div><strong>{healthStatus === 'connected' ? 'Système opérationnel' : healthStatus === 'checking' ? 'Vérification en cours' : 'API indisponible'}</strong><small>{healthStatus === 'connected' ? 'API et base de données connectées' : 'État réel de l’API et MongoDB'}</small></div></div><div className="sidebar-user"><span className="avatar">{(currentUser.fullName || 'U').slice(0, 1).toUpperCase()}</span><div className="user-copy"><strong>{currentUser.fullName}</strong><small>{roleLabel(currentUser.role)}</small></div><button className="icon-button logout-button" onClick={logout} title="Se déconnecter" aria-label="Se déconnecter"><LogOut size={16} /></button></div></div>
    </aside>
    {sidebarOpen && <button className="mobile-scrim" onClick={() => setSidebarOpen(false)} aria-label="Fermer le menu" />}
    <a className="skip-link" href="#main-content">Aller au contenu</a>
    <main className="main-shell" id="main-content" tabIndex="-1">
      <header className="topbar"><button className="icon-button mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Ouvrir le menu"><Menu size={19} /></button><div className="breadcrumb"><span>CyberTrack</span><ChevronRight size={13} /><strong>{activeItem.label}</strong></div><div className="topbar-right"><span className={`api-indicator ${healthStatus}`}><i />{healthStatus === 'connected' ? 'API connectée' : healthStatus === 'checking' ? 'Vérification' : 'API indisponible'}</span><span className="topbar-avatar" aria-label={currentUser.fullName}>{(currentUser.fullName || 'U').slice(0, 1).toUpperCase()}</span></div></header>
      <div className="content-area">
        {view === 'dashboard' ? <Dashboard setView={setView} /> : <ResourcePage key={view} view={view} currentUser={currentUser} />}
      </div>
      <footer className="app-footer"><span>CyberTrack · Gestion des vulnérabilités</span><span>Scans issus des enregistrements et imports disponibles.</span></footer>
    </main>
  </div>
}

export default App
