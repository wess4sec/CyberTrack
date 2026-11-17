import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const assetId = '64b000000000000000000001'
const vulnerabilityId = '64b000000000000000000002'
const assigneeId = '64b000000000000000000003'

function response(data, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  }
}

function paginated(data) {
  return { success: true, data, pagination: { page: 1, limit: 20, total: data.length, pages: data.length ? 1 : 0 } }
}

describe('parcours de création de remédiation', () => {
  beforeEach(() => {
    window.fetch = vi.fn(async (url, options = {}) => {
      const path = String(url).replace(/^\/api/, '').split('?')[0]

      if (path === '/auth/me') {
        return response({ success: false, error: { message: 'Authentication is required.' } }, 401)
      }
      if (path === '/auth/login') {
        return response({ success: true, data: { user: { _id: assigneeId, fullName: 'Analyste Cyber', role: 'SECURITY_ANALYST' } } })
      }
      if (path === '/health') {
        return response({ success: true, data: { database: 'connected' } })
      }
      if (path === '/dashboard/overview') {
        return response({ success: true, data: { totalVulnerabilities: 1, activeAssets: 1, openRemediationTasks: 0, overdueRemediationTasks: 0, totalScans: 0 } })
      }
      if (path === '/dashboard/severity') return response({ success: true, data: [{ severity: 'HIGH', count: 1 }] })
      if (path === '/dashboard/vulnerability-status') return response({ success: true, data: [] })
      if (path === '/dashboard/monthly-trends' || path.startsWith('/dashboard/')) return response({ success: true, data: [] })
      if (path === '/remediation' && options.method === 'POST') {
        return response({ success: true, data: { _id: '64b000000000000000000004' } }, 201)
      }
      if (path === '/scans' || path === '/remediation') return response(paginated([]))
      if (path === '/assets') return response(paginated([{ _id: assetId, hostname: 'srv-production', ipAddress: '192.0.2.10' }]))
      if (path === '/vulnerabilities') return response(paginated([{ _id: vulnerabilityId, cveId: 'CVE-2099-000001', title: 'Faille de démonstration', severity: 'HIGH' }]))
      if (path === '/users/assignees') return response(paginated([{ _id: assigneeId, fullName: 'Analyste Cyber', department: 'Sécurité' }]))
      throw new Error(`Unexpected API request: ${options.method || 'GET'} ${url}`)
    })
  })

  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  it('crée une tâche en associant des enregistrements recherchés plutôt que des ObjectId saisis', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(await screen.findByLabelText('Adresse e-mail'), 'analyste@example.test')
    await user.type(screen.getByLabelText('Mot de passe'), 'mot-de-passe-test')
    await user.click(screen.getByRole('button', { name: 'Se connecter' }))
    await screen.findByRole('heading', { name: 'Vue d’ensemble' })
    await user.click(screen.getByRole('button', { name: 'Remédiation' }))
    await screen.findByRole('heading', { name: 'Remédiation' })
    await user.click(screen.getByRole('button', { name: 'Nouvelle tâche' }))

    const vulnerability = screen.getByRole('combobox', { name: 'Vulnérabilité' })
    await user.click(vulnerability)
    await user.click(await screen.findByRole('option', { name: /CVE-2099-000001/ }))

    const asset = screen.getByRole('combobox', { name: 'Actif' })
    await user.click(asset)
    await user.click(await screen.findByRole('option', { name: /srv-production/ }))

    const assignee = screen.getByRole('combobox', { name: 'Assigné à' })
    await user.click(assignee)
    await user.click(await screen.findByRole('option', { name: /Analyste Cyber/ }))

    await user.type(screen.getByLabelText('Titre'), 'Corriger la faille')
    await user.type(screen.getByLabelText('Description'), 'Mettre à jour le composant concerné.')
    await user.selectOptions(screen.getByLabelText('Priorité'), 'HIGH')
    await user.selectOptions(screen.getByLabelText('Statut'), 'OPEN')
    fireEvent.change(screen.getByLabelText('Échéance'), { target: { value: '2027-01-02T03:04' } })
    await user.click(screen.getByRole('button', { name: 'Créer' }))

    await waitFor(() => {
      const createRequest = window.fetch.mock.calls.find(([url, options]) =>
        String(url).startsWith('/api/remediation') && options?.method === 'POST'
      )
      expect(createRequest).toBeDefined()
      expect(JSON.parse(createRequest[1].body)).toMatchObject({
        vulnerabilityId,
        assetId,
        assignedTo: assigneeId,
        title: 'Corriger la faille',
      })
    })
  })

  it('affiche les indicateurs du dashboard et les événements réellement renvoyés par l’API', async () => {
    window.fetch.mockImplementation(async url => {
      const path = String(url).replace(/^\/api/, '').split('?')[0]
      if (path === '/auth/me') {
        return response({ success: true, data: { user: { _id: assigneeId, fullName: 'Analyste Cyber', role: 'SECURITY_ANALYST' } } })
      }
      if (path === '/health') return response({ success: true, data: { database: 'connected' } })
      if (path === '/dashboard/overview') {
        return response({ success: true, data: { totalVulnerabilities: 120, activeAssets: 8, openRemediationTasks: 3, overdueRemediationTasks: 1, totalScans: 12, completedRemediationTasks: 4 } })
      }
      if (path === '/dashboard/severity') return response({ success: true, data: [{ severity: 'CRITICAL', count: 7 }, { severity: 'HIGH', count: 12 }] })
      if (path === '/dashboard/vulnerability-status') return response({ success: true, data: [{ status: 'ACTIVE', count: 19 }] })
      if (path === '/dashboard/monthly-trends') return response({ success: true, data: [{ year: 2026, month: 1, count: 3 }, { year: 2026, month: 2, count: 6 }] })
      if (path.startsWith('/dashboard/')) return response({ success: true, data: [] })
      if (path === '/scans') {
        return response(paginated([{ _id: 'scan-1', assetId: { hostname: 'web-01' }, scanType: 'Import manuel', status: 'IMPORTED', startedAt: '2026-02-14T12:00:00.000Z' }]))
      }
      if (path === '/remediation') {
        return response(paginated([{ _id: 'task-1', title: 'Mettre à jour le service', assignedTo: { fullName: 'Analyste Cyber' }, status: 'COMPLETED', createdAt: '2026-02-15T12:00:00.000Z' }]))
      }
      throw new Error(`Unexpected API request: ${url}`)
    })

    render(<App />)

    await screen.findByRole('heading', { name: 'Vue d’ensemble' })
    expect(screen.getAllByText('120')).toHaveLength(2)
    expect(screen.getByRole('img', { name: /Tendance mensuelle des vulnérabilités publiées/ })).toBeTruthy()
    expect(screen.getByText('web-01')).toBeTruthy()
    expect(screen.getByRole('progressbar', { name: 'Tâches récentes terminées' }).getAttribute('aria-valuenow')).toBe('1')
  })

  it('parcourt les cinq espaces de gestion et charge leur endpoint existant', async () => {
    window.fetch.mockImplementation(async url => {
      const path = String(url).replace(/^\/api/, '').split('?')[0]
      if (path === '/auth/me') {
        return response({ success: true, data: { user: { _id: 'admin-1', fullName: 'Administrateur', role: 'ADMIN' } } })
      }
      if (path === '/health') return response({ success: true, data: { database: 'connected' } })
      if (path.startsWith('/dashboard/')) return response({ success: true, data: [] })
      if (['/vulnerabilities', '/assets', '/scans', '/remediation', '/users'].includes(path)) return response(paginated([]))
      throw new Error(`Unexpected API request: ${url}`)
    })

    const user = userEvent.setup()
    render(<App />)
    await screen.findByRole('heading', { name: 'Vue d’ensemble' })

    const pages = [
      ['Vulnérabilités', '/vulnerabilities'],
      ['Actifs', '/assets'],
      ['Scans', '/scans'],
      ['Remédiation', '/remediation'],
      ['Utilisateurs', '/users'],
    ]

    for (const [label, endpoint] of pages) {
      await user.click(screen.getByRole('button', { name: label }))
      await screen.findByRole('heading', { name: label })
      await waitFor(() => {
        expect(window.fetch.mock.calls.some(([url]) => String(url).startsWith(`/api${endpoint}?`))).toBe(true)
      })
    }
  })
})
