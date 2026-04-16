import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIContext } from 'astro';

export async function GET(context: APIContext) {
  const posts = await getCollection('blog', ({ data }) => !data.draft);

  return rss({
    title: 'Cullis — Journal',
    description: 'Posts and updates from the Cullis team.',
    site: context.site ?? 'https://cullis.io',
    items: posts
      .sort((a, b) => new Date(b.data.date).getTime() - new Date(a.data.date).getTime())
      .map((post) => ({
        title: post.data.title,
        description: post.data.description,
        pubDate: new Date(post.data.date),
        link: `/blog/${post.id}/`,
        author: post.data.author,
      })),
    customData: `<language>en-us</language>`,
  });
}
