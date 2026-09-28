/**
 * Custom auth strategies and `_strategy`.
 *
 * The plugin reads a user without `_strategy` as one that server code loaded itself,
 * not a login, and doesn't hold it to TOTP. Payload's own strategies set `_strategy`,
 * but a custom strategy may not, so the plugin tags those users with the strategy's
 * name. Tagging a strategy named `api-key` or `totp` would make its users pass as an
 * API key or as already verified, so those names are refused at startup.
 */

import type { AuthStrategy, Config } from 'payload'

import { payloadTotp } from '../src/index'
import { strategy as totpStrategy } from '../src/strategy'
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

function buildConfig(): Config {
	return {
		collections: [
			{
				slug: 'users',
				auth: { strategies: [buildStrategy('sso', { id: 'user-1', collection: 'users' })] },
				fields: [],
			},
			{
				slug: 'members',
				auth: {
					strategies: [
						buildStrategy('member-sso', { id: 'member-1', collection: 'members' }),
					],
				},
				fields: [],
			},
			{ slug: 'posts', fields: [] },
		],
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const collectionBySlug = (config: Config, slug: string): any =>
	config.collections!.find((collection) => collection.slug === slug)

describe('payloadTotp and custom strategies', () => {
	test("tags users of the TOTP collection's custom strategies", async () => {
		const users = collectionBySlug(payloadTotp({ collection: 'users' })(buildConfig()), 'users')
		const sso = users.auth.strategies.find((entry: AuthStrategy) => entry.name === 'sso')

		const result = await sso.authenticate(authenticateArgs)

		expect(result.user._strategy).toBe('sso')
	})

	test('keeps its own TOTP strategy first and unwrapped', () => {
		const users = collectionBySlug(payloadTotp({ collection: 'users' })(buildConfig()), 'users')

		expect(users.auth.strategies[0]).toBe(totpStrategy)
	})

	test('tags users of custom strategies on other auth collections', async () => {
		const members = collectionBySlug(
			payloadTotp({ collection: 'users' })(buildConfig()),
			'members',
		)

		const result = await members.auth.strategies[0].authenticate(authenticateArgs)

		expect(result.user._strategy).toBe('member-sso')
	})

	// The admin redirects and the TOTP cookie rely on the name even when access isn't wrapped.
	test('still tags custom-strategy users when the access wrapper is disabled', async () => {
		const users = collectionBySlug(
			payloadTotp({ collection: 'users', disableAccessWrapper: true })(buildConfig()),
			'users',
		)
		const sso = users.auth.strategies.find((entry: AuthStrategy) => entry.name === 'sso')

		const result = await sso.authenticate(authenticateArgs)

		expect(result.user._strategy).toBe('sso')
	})

	test('leaves collections without auth alone', () => {
		const posts = collectionBySlug(payloadTotp({ collection: 'users' })(buildConfig()), 'posts')

		expect(posts.auth).toBeUndefined()
	})

	test('refuses a custom strategy with a reserved name at config time', () => {
		const config = buildConfig()
		collectionBySlug(config, 'members').auth.strategies.push(buildStrategy('totp', null))

		expect(() => payloadTotp({ collection: 'users' })(config)).toThrow('"totp"')
	})

	test('leaves custom strategies untouched when disabled', () => {
		const config = buildConfig()
		const original = collectionBySlug(config, 'users').auth.strategies[0]

		const users = collectionBySlug(
			payloadTotp({ collection: 'users', disabled: true })(config),
			'users',
		)

		expect(users.auth.strategies).toHaveLength(1)
		expect(users.auth.strategies[0]).toBe(original)
	})
})
