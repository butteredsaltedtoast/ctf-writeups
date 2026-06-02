import { defineCollection } from 'astro:content';
import { glob, file } from 'astro/loaders';
import { z } from 'astro/zod';

const writeups = defineCollection({
	loader: glob({ base: './src/content/writeups', pattern: '**/*.{md,mdx}' }),
	schema: ({ image }) =>
		z.object({
			title: z.string(),
			description: z.string(),
			pubDate: z.coerce.date(),
			updatedDate: z.coerce.date().optional(),
			heroImage: z.optional(image()),
			
			ctf: z.string(),
			category: z.enum(['pwn', 'web', 'crypto', 'reversing', 'misc', 'osint', 'forensics']),
		}),
});

const projects = defineCollection({

	loader: glob({ base: './src/content/projects', pattern: '**/*.{md,mdx}' }),
	schema: ({ image }) =>
		z.object({
			title: z.string(),
			description: z.string(),
			pubDate: z.coerce.date(),

			github: z.string(),
			stack: z.array(z.string()),
		}),

});

const ctfs = defineCollection({
	loader: file('./src/content/ctfs.yaml'),
	schema: z.object({
		name: z.string(),
		date: z.coerce.date(),
		team: z.string(),
		placement: z.number().optional(),
		division: z.string().optional(),
		status: z.string().optional(),
	}),
});

export const collections = { writeups, projects, ctfs };