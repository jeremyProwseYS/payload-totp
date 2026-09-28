/**
 * Which users have to pass TOTP.
 *
 * Payload's scheduled-publish job runs as the user who scheduled it, loaded straight
 * from the database: enrolled (`hasTotp: true`) but with no `_strategy`, because no auth
 * strategy produced it. The access wrapper used to deny every enrolled user that wasn't
 * authenticated through the `totp` strategy, so the job failed with `Forbidden` and the
 * document stayed in draft. Only a login -- a user carrying a `_strategy` -- is held to
 * TOTP now.
 */

import type { PayloadTOTPConfig, UserWithTotp } from '../src/types'

import { totpAccess } from '../src/totpAccess'
import {
	isExemptStrategy,
	requiresTotpVerification,
} from '../src/utilities/requiresTotpVerification'

const pluginOptions: PayloadTOTPConfig = { collection: 'users', exemptStrategies: ['okta'] }

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

describe('requiresTotpVerification', () => {
	test.each<[string, Partial<UserWithTotp>, boolean]>([
		['requires it of an enrolled password login', { _strategy: 'local-jwt' }, true],
		['requires it of an enrolled custom-strategy login', { _strategy: 'sso' }, true],
		['not of an enrolled login that passed TOTP', { _strategy: 'totp' }, false],
		['not of an enrolled API-key login', { _strategy: 'api-key' }, false],
		['not of an enrolled login through an exempt strategy', { _strategy: 'okta' }, false],
		['not of a login that has not enrolled', { _strategy: 'local-jwt', hasTotp: false }, false],
		['not of an enrolled user loaded by server code', {}, false],
	])('%s', (_description, overrides, expected) => {
		expect(requiresTotpVerification({ pluginOptions, user: buildUser(overrides) })).toBe(
			expected,
		)
	})
})

function buildAccessArgs(user: UserWithTotp) {
	return {
		req: {
			payload: { config: { custom: { totp: { pluginOptions } } } },
			user,
		},
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any
}

// How Payload's schedulePublish task loads the scheduling user: `findByID` plus
// `collection`, with no auth strategy involved.
const scheduledPublishUser = buildUser({})

describe('totpAccess', () => {
	test('lets the scheduled-publish user through to the inner access function', async () => {
		const inner = jest.fn(() => true)

		await expect(totpAccess(inner)(buildAccessArgs(scheduledPublishUser))).resolves.toBe(true)
		expect(inner).toHaveBeenCalledTimes(1)
	})

	test('returns what the inner access function decides for that user', async () => {
		const where = { tenant: { equals: 'tenant-1' } }
		const args = buildAccessArgs(scheduledPublishUser)

		await expect(totpAccess(() => false)(args)).resolves.toBe(false)
		await expect(totpAccess(() => where)(args)).resolves.toBe(where)
	})

	test('allows that user when there is no inner access function', async () => {
		await expect(totpAccess()(buildAccessArgs(scheduledPublishUser))).resolves.toBe(true)
	})

	test('still denies an enrolled password login without asking the inner function', async () => {
		const inner = jest.fn(() => true)
		const args = buildAccessArgs(buildUser({ _strategy: 'local-jwt' }))

		await expect(totpAccess(inner)(args)).resolves.toBe(false)
		expect(inner).not.toHaveBeenCalled()
	})

	test('denies an enrolled custom-strategy login', async () => {
		const args = buildAccessArgs(buildUser({ _strategy: 'sso' }))

		await expect(totpAccess(() => true)(args)).resolves.toBe(false)
	})

	test('lets an exempt strategy through to the inner access function', async () => {
		const inner = jest.fn(() => true)
		const args = buildAccessArgs(buildUser({ _strategy: 'okta' }))

		await expect(totpAccess(inner)(args)).resolves.toBe(true)
		expect(inner).toHaveBeenCalledTimes(1)
	})
})
