import { type Page, expect } from '@playwright/test'

import { test } from './fixtures'

test.describe('schedule publish', () => {
	let page: Page
	let teardown: VoidFunction
	let baseURL: string

	test.beforeAll(async ({ setup, browser, helpers }) => {
		const setupResult = await setup({ forceSetup: true, limitToLogin: true })
		teardown = setupResult.teardown
		baseURL = setupResult.baseURL
		const context = await browser.newContext()
		page = await context.newPage()

		await helpers.createFirstUser({ page, baseURL })
		await page.waitForURL(/^(.*?)\/admin\/setup-totp(\?back=.*?)?$/g)
		await helpers.setupTotp({ page, baseURL })
	})

	test.afterAll(async () => {
		await teardown()
		await page.close()
	})

	test('publishes a draft scheduled by a user with TOTP', async () => {
		const createRes = await page.request.post(`${baseURL}/api/pages?draft=true`, {
			data: { _status: 'draft', title: 'Launch announcement' },
		})
		expect(createRes.ok()).toBeTruthy()

		const { doc } = await createRes.json()
		expect(doc._status).toBe('draft')

		const scheduleRes = await page.request.post(`${baseURL}/schedule-publish`, {
			data: { id: doc.id },
		})
		expect(scheduleRes.ok()).toBeTruthy()
		await expect(scheduleRes.json()).resolves.toEqual({ _status: 'published' })
	})
})
