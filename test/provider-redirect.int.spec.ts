/**
 * The admin provider's redirects follow the same rule as the access wrapper: an
 * enrolled login goes to the verify page unless it passed TOTP or came through an
 * exempt strategy, and `forceSetup` doesn't send exempt logins to the setup page.
 */

jest.mock('next/headers.js', () => ({
	headers: async () => new Headers({ 'x-pathname': '/admin' }),
}))

jest.mock('next/navigation.js', () => ({
	redirect: jest.fn(),
}))

jest.mock('@payloadcms/ui/shared', () => ({
	formatAdminURL: ({ adminRoute, path }: { adminRoute: string; path: string }) =>
		`${adminRoute}${path}`,
}))

// The client half needs a browser; only whether the server half redirects matters here.
jest.mock('../src/components/Provider/index.client', () => ({
	__esModule: true,
	default: () => null,
}))

import { redirect } from 'next/navigation.js'

import type { PayloadTOTPConfig } from '../src/types'

import { TOTPProvider } from '../src/components/Provider/index'

const redirectMock = jest.mocked(redirect)

function renderProvider(pluginOptions: PayloadTOTPConfig, user: Record<string, unknown>) {
	return TOTPProvider({
		children: null,
		payload: { config: { routes: { admin: '/admin' }, serverURL: '' } },
		pluginOptions,
		user: { id: 'user-1', collection: 'users', ...user },
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any)
}

beforeEach(() => {
	redirectMock.mockReset()
})

describe('TOTPProvider', () => {
	test('sends an enrolled password login to the verify page', async () => {
		await renderProvider({ collection: 'users' }, { _strategy: 'local-jwt', hasTotp: true })

		expect(redirectMock).toHaveBeenCalledWith('/admin/verify-totp?back=%2Fadmin')
	})

	test('leaves an enrolled login through an exempt strategy where it is', async () => {
		await renderProvider(
			{ collection: 'users', exemptStrategies: ['okta'] },
			{ _strategy: 'okta', hasTotp: true },
		)

		expect(redirectMock).not.toHaveBeenCalled()
	})

	test('sends a login without TOTP to the setup page when forceSetup is on', async () => {
		await renderProvider(
			{ collection: 'users', forceSetup: true },
			{ _strategy: 'local-jwt', hasTotp: false },
		)

		expect(redirectMock).toHaveBeenCalledWith('/admin/setup-totp?back=%2Fadmin')
	})

	test('does not force setup on a login through an exempt strategy', async () => {
		await renderProvider(
			{ collection: 'users', exemptStrategies: ['okta'], forceSetup: true },
			{ _strategy: 'okta', hasTotp: false },
		)

		expect(redirectMock).not.toHaveBeenCalled()
	})
})
