/**
 * Custom auth strategies and `_strategy`.
 *
 * The plugin reads a user without `_strategy` as one that server code loaded itself,
 * not a login, and doesn't hold it to TOTP. Payload's own strategies set `_strategy`,
 * but a custom strategy may not, so the plugin tags those users with the strategy's
 * name. Tagging a strategy named `api-key` or `totp` would make its users pass as an
 * API key or as already verified, so those names are refused at startup.
 */

import type { AuthStrategy } from 'payload'

import { withStrategyName } from '../src/utilities/withStrategyName'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const authenticateArgs = { headers: new Headers(), payload: {} } as any

function buildStrategy(name: string, user: null | Record<string, unknown>): AuthStrategy {
	return {
		name,
		authenticate: async () => ({
			responseHeaders: new Headers({ 'x-strategy': name }),
			user,
		}),
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any
}

describe('withStrategyName', () => {
	test('tags a user the strategy left untagged with the strategy name', async () => {
		const wrapped = withStrategyName(
			buildStrategy('sso', { id: 'user-1', collection: 'users' }),
		)

		const result = await wrapped.authenticate(authenticateArgs)

		expect(result.user).toEqual({ id: 'user-1', _strategy: 'sso', collection: 'users' })
	})

	test('keeps a strategy name the strategy set itself', async () => {
		const wrapped = withStrategyName(
			buildStrategy('sso', { id: 'user-1', _strategy: 'sso-v2', collection: 'users' }),
		)

		const result = await wrapped.authenticate(authenticateArgs)

		expect(result.user?._strategy).toBe('sso-v2')
	})

	test('passes through a result without a user', async () => {
		const result = await withStrategyName(buildStrategy('sso', null)).authenticate(
			authenticateArgs,
		)

		expect(result.user).toBeNull()
	})

	test('keeps the response headers', async () => {
		const wrapped = withStrategyName(
			buildStrategy('sso', { id: 'user-1', collection: 'users' }),
		)

		const result = await wrapped.authenticate(authenticateArgs)

		expect(result.responseHeaders?.get('x-strategy')).toBe('sso')
	})

	// The TOTP strategy finds the strategy to delegate to by the name in its cookie.
	test('keeps the strategy name', () => {
		expect(withStrategyName(buildStrategy('sso', null)).name).toBe('sso')
	})

	test('lets errors from the strategy propagate', async () => {
		const failing: AuthStrategy = {
			name: 'sso',
			authenticate: async () => {
				throw new Error('provider down')
			},
		}

		await expect(withStrategyName(failing).authenticate(authenticateArgs)).rejects.toThrow(
			'provider down',
		)
	})

	test.each(['api-key', 'totp'])('refuses a strategy named %s', (name) => {
		expect(() => withStrategyName(buildStrategy(name, null))).toThrow(`"${name}"`)
	})
})
