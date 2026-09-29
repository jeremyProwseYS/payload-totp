import type { AuthStrategy } from 'payload'

import { API_KEY_STRATEGY_NAME, TOTP_STRATEGY_NAME } from '../constants.js'

// Once its users were tagged with it, a custom strategy with one of these names would
// pass as an API key or as a login that already passed TOTP.
const RESERVED_STRATEGY_NAMES: string[] = [API_KEY_STRATEGY_NAME, TOTP_STRATEGY_NAME]

/**
 * Wraps a custom auth strategy so every user it authenticates carries the strategy's
 * name in `_strategy`, as the users of Payload's built-in strategies do.
 *
 * Payload leaves `_strategy` to each strategy, and a custom one may omit it. The name is
 * what the TOTP cookie records, so the TOTP strategy can delegate back to this one, and
 * what `exemptStrategies` is matched against. With `limitToLogin` on, the plugin also
 * reads a missing `_strategy` as "not a login" (see `requiresTotpVerification`), so
 * without this such a login would skip TOTP.
 */
export function withStrategyName(strategy: AuthStrategy): AuthStrategy {
	if (RESERVED_STRATEGY_NAMES.includes(strategy.name)) {
		throw new Error(
			`payload-totp: an auth strategy is named "${strategy.name}", which the plugin reserves. Rename the strategy.`,
		)
	}

	return {
		...strategy,
		authenticate: async (args) => {
			const result = await strategy.authenticate(args)

			if (!result.user || result.user._strategy) {
				return result
			}

			return {
				...result,
				user: {
					...result.user,
					_strategy: strategy.name,
				},
			}
		},
	}
}
