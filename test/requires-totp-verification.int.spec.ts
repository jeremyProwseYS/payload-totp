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
