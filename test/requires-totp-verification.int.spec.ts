/**
 * Which users have to pass TOTP.
 *
 * Payload's scheduled-publish job runs as the user who scheduled it, loaded straight
 * from the database: enrolled (`hasTotp: true`) but with no `_strategy`, because no auth
 * strategy produced it. By default the access wrapper denies every enrolled user that
 * wasn't authenticated through the `totp` strategy, so the job fails with `Forbidden` and
 * the document stays in draft. With `limitToLogin` on, only a login -- a user carrying a
 * `_strategy` -- is held to TOTP, and the job runs.
 */

import type { PayloadTOTPConfig, UserWithTotp } from '../src/types'

import { totpAccess } from '../src/totpAccess'
import {
	isExemptStrategy,
	requiresTotpVerification,
} from '../src/utilities/requiresTotpVerification'

const pluginOptions: PayloadTOTPConfig = { collection: 'users', exemptStrategies: ['okta'] }
const limitToLoginOptions: PayloadTOTPConfig = { ...pluginOptions, limitToLogin: true }

function buildUser(overrides: Partial<UserWithTotp>): UserWithTotp {
	return {
		id: 'user-1',
		collection: 'users',
		hasTotp: true,
		...overrides,
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any
}

describe('isExemptStrategy', () => {
	test.each([
		['exempts API keys without being listed', 'api-key', true],
		['exempts a listed strategy', 'okta', true],
		['does not exempt password logins', 'local-jwt', false],
		['does not exempt the TOTP strategy', 'totp', false],
	])('%s', (_description, strategyName, expected) => {
		const user = buildUser({ _strategy: strategyName })

		expect(isExemptStrategy({ pluginOptions, user })).toBe(expected)
	})

	test('does not exempt a user without a strategy', () => {
		expect(isExemptStrategy({ pluginOptions, user: buildUser({}) })).toBe(false)
	})

	test('exempts API keys when exemptStrategies is not set', () => {
		const user = buildUser({ _strategy: 'api-key' })

		expect(isExemptStrategy({ pluginOptions: { collection: 'users' }, user })).toBe(true)
	})
})

// `limitToLogin` only changes what happens to a user without a `_strategy`, so a login is
// held to TOTP the same way either way.
describe.each([
	['by default', pluginOptions],
	['with limitToLogin', limitToLoginOptions],
])('requiresTotpVerification %s', (_label, options) => {
	test.each<[string, Partial<UserWithTotp>, boolean]>([
		['requires it of an enrolled password login', { _strategy: 'local-jwt' }, true],
		['requires it of an enrolled custom-strategy login', { _strategy: 'sso' }, true],
		['not of an enrolled login that passed TOTP', { _strategy: 'totp' }, false],
		['not of an enrolled API-key login', { _strategy: 'api-key' }, false],
		['not of an enrolled login through an exempt strategy', { _strategy: 'okta' }, false],
		['not of a login that has not enrolled', { _strategy: 'local-jwt', hasTotp: false }, false],
	])('%s', (_description, overrides, expected) => {
		expect(
			requiresTotpVerification({ pluginOptions: options, user: buildUser(overrides) }),
		).toBe(expected)
	})
})

describe('requiresTotpVerification for a user loaded by server code', () => {
	test('requires it of an enrolled user by default', () => {
		expect(requiresTotpVerification({ pluginOptions, user: buildUser({}) })).toBe(true)
	})

	test('does not require it of an enrolled user with limitToLogin', () => {
		const user = buildUser({})

		expect(requiresTotpVerification({ pluginOptions: limitToLoginOptions, user })).toBe(false)
	})

	test('does not require it of a user who has not enrolled', () => {
		expect(
			requiresTotpVerification({ pluginOptions, user: buildUser({ hasTotp: false }) }),
		).toBe(false)
	})
})

function buildAccessArgs(user: UserWithTotp, options: PayloadTOTPConfig = pluginOptions) {
	return {
		req: {
			payload: { config: { custom: { totp: { pluginOptions: options } } } },
			user,
		},
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any
}

// How Payload's schedulePublish task loads the scheduling user: `findByID` plus
// `collection`, with no auth strategy involved.
const scheduledPublishUser = buildUser({})

describe('totpAccess', () => {
	test('denies the scheduled-publish user by default without asking the inner function', async () => {
		const inner = jest.fn(() => true)

		await expect(totpAccess(inner)(buildAccessArgs(scheduledPublishUser))).resolves.toBe(false)
		expect(inner).not.toHaveBeenCalled()
	})

	test('lets an exempt strategy through to the inner access function', async () => {
		const inner = jest.fn(() => true)
		const args = buildAccessArgs(buildUser({ _strategy: 'okta' }))

		await expect(totpAccess(inner)(args)).resolves.toBe(true)
		expect(inner).toHaveBeenCalledTimes(1)
	})
})

describe('totpAccess with limitToLogin', () => {
	test('lets the scheduled-publish user through to the inner access function', async () => {
		const inner = jest.fn(() => true)
		const args = buildAccessArgs(scheduledPublishUser, limitToLoginOptions)

		await expect(totpAccess(inner)(args)).resolves.toBe(true)
		expect(inner).toHaveBeenCalledTimes(1)
	})

	test('returns what the inner access function decides for that user', async () => {
		const where = { tenant: { equals: 'tenant-1' } }
		const args = buildAccessArgs(scheduledPublishUser, limitToLoginOptions)

		await expect(totpAccess(() => false)(args)).resolves.toBe(false)
		await expect(totpAccess(() => where)(args)).resolves.toBe(where)
	})

	test('allows that user when there is no inner access function', async () => {
		const args = buildAccessArgs(scheduledPublishUser, limitToLoginOptions)

		await expect(totpAccess()(args)).resolves.toBe(true)
	})

	test('still denies an enrolled password login without asking the inner function', async () => {
		const inner = jest.fn(() => true)
		const args = buildAccessArgs(buildUser({ _strategy: 'local-jwt' }), limitToLoginOptions)

		await expect(totpAccess(inner)(args)).resolves.toBe(false)
		expect(inner).not.toHaveBeenCalled()
	})

	test('still denies an enrolled custom-strategy login', async () => {
		const args = buildAccessArgs(buildUser({ _strategy: 'sso' }), limitToLoginOptions)

		await expect(totpAccess(() => true)(args)).resolves.toBe(false)
	})
})
