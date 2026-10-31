import { z } from 'zod'

// Leaf wire vocabulary: this module must never import admission, export, runtime or command modules.
export const IMAGE_MESSAGE_CAPABILITY = 'message.images.v1'
export const SESSION_MEDIA_CAPABILITY = 'session.media.v1'
export const MAX_IMAGE_BYTES = 16 * 1024 * 1024
export const MAX_IMAGE_PIXELS = 32_000_000
export const MAX_IMAGE_DIMENSION = 16_384
export const imageReference = z.strictObject({ type: z.literal('image'), file_id: z.uuid() })
export const imageMediaType = z.enum(['image/png', 'image/jpeg', 'image/webp', 'image/gif'])
