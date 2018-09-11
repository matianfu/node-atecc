module.exports = function getCorrectBuffer (content) {
  const arrayBuffer = new ArrayBuffer(content.length)
  const uint8Array = new Uint8Array(arrayBuffer)

  for (let i = 0; i < content.length; i++) { 
    uint8Array[i] = content[i] 
  }

  return arrayBuffer.slice(0)
}
