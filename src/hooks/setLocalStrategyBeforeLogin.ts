import type { CollectionBeforeLoginHook } from 'payload'

import type { AuthenticatedUser } from '../types.js'

import { LOCAL_JWT_STRATEGY_NAME } from '../constants.js'

/**
 * Tags a password login's user with `_strategy`.
 *
 * Payload's login operation tags the user itself, but reset password -- which logs the
 * user in too -- only does so when the collection uses sessions. Otherwise the rest of
 * that request runs with an untagged `req.user`, which the plugin would read as "not a
 * login" and not hold to TOTP in the app's own `afterLogin` and `afterOperation` hooks.
 * Both operations put the user this hook returns on `req.user`.
 */
export const setLocalStrategyBeforeLogin: CollectionBeforeLoginHook<AuthenticatedUser> = ({
	user,
}) => {
	if (user._strategy) {
		return user
	}

	return {
		...user,
		_strategy: LOCAL_JWT_STRATEGY_NAME,
	}
}
