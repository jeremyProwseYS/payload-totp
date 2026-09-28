import type { CollectionConfig } from 'payload'

export const pages: CollectionConfig = {
	slug: 'pages',
	admin: {
		useAsTitle: 'title',
	},
	fields: [
		{
			name: 'title',
			type: 'text',
			required: true,
		},
	],
	versions: {
		drafts: {
			schedulePublish: true,
		},
	},
}
