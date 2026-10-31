import { crc32, deflateSync } from 'node:zlib'

/** One real static RGBA PNG, including valid chunk CRCs and compressed scanline. */
export function mediaPixelPNG(): Buffer {
  const chunk = (type: string, data: Buffer) => {
    const name = Buffer.from(type), size = Buffer.alloc(4), checksum = Buffer.alloc(4)
    size.writeUInt32BE(data.length); checksum.writeUInt32BE(crc32(Buffer.concat([name, data])))
    return Buffer.concat([size, name, data, checksum])
  }
  const header = Buffer.alloc(13)
  header.writeUInt32BE(1, 0); header.writeUInt32BE(1, 4); header[8] = 8; header[9] = 6
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header),
    chunk('IDAT', deflateSync(Buffer.from([0, 255, 0, 0, 255]))), chunk('IEND', Buffer.alloc(0))])
}
