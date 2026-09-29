import type { PayloadTOTPConfig, UserWithTotp } from '../types.js'

import { API_KEY_STRATEGY_NAME, TOTP_STRATEGY_NAME } from '../constants.js'

type Args = {
	pluginOptions: PayloadTOTPConfig
	user: UserWithTotp
}

/**
 * Whether the strategy that authenticated the user skips TOTP altogether: an API key,
 * or one the app listed in `exemptStrategies` -- for example an SSO provider that runs
 * its own second factor.
 */
export function isExemptStrategy({ pluginOptions, user }: Args): boolean {
	const strategyName = user._strategy

	if (!strategyName) {
		return false
	}

	return (
		strategyName === API_KEY_STRATEGY_NAME ||
		(pluginOptions.exemptStrategies ?? []).includes(strategyName)
	)
}

/**
 * Whether the user has to pass TOTP before the request may go further.
 *
 * With `limitToLogin` on, only a login is held to TOTP. A user that no auth strategy
 * produced was loaded by server code acting on its behalf -- Payload's scheduled-publish
 * job, for one -- and never presented credentials a second factor could back up. Every
 * login carries a `_strategy`: Payload's own strategies and operations set it, and the
 * plugin sets it for custom strategies and reset-password logins that would otherwise
 * lack one (see `withStrategyName` and `setLocalStrategyBeforeLogin`).
 *
 * It's off by default, because it lets server code act as an enrolled user without the
 * code: the app has to trust whatever it passes to the Local API as `user`.
 */
export function requiresTotpVerification({ pluginOptions, user }: Args): boolean {
	if (!user.hasTotp) {
		return false
	}

	if (!user._strategy) {
		return !pluginOptions.limitToLogin
	}

	if (user._strategy === TOTP_STRATEGY_NAME) {
		return false
	}

	return !isExemptStrategy({ pluginOptions, user })
}
