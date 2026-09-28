import configPromise from '@payload-config'
import { getPayload } from 'payload'

// Stands in for the admin UI's schedule drawer, which only accepts future dates. It
// queues the same `schedulePublish` job the drawer queues, as the logged-in caller, and
// runs it at once, so a spec can assert the outcome without waiting on a clock.
export const POST = async (request: Request) => {
	const payload = await getPayload({ config: configPromise })
	const { user } = await payload.auth({ headers: request.headers })

	if (!user) {
		return Response.json({ message: 'Unauthorized' }, { status: 401 })
	}

	const { id } = (await request.json()) as { id: string }

	const job = await payload.jobs.queue({
		input: {
			type: 'publish',
			doc: { relationTo: 'pages', value: id },
			user: user.id,
		},
		task: 'schedulePublish',
	})

	await payload.jobs.runByID({ id: job.id })

	const page = await payload.findByID({ id, collection: 'pages' })

	return Response.json({ _status: page._status })
}
