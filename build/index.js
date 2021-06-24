// Builder script that updates the website from this repository to live
// Only uses native Node.Js libraries, because I was bored at work.
const https = require("https")
const crypto = require("crypto")
const fs = require("fs")
const zlib = require("zlib")
// Format: https://github.com/User/repo/archive/master.tar.gz
const ZipLocation = "https://github.com/Esinko-net/Esinko.net/archive/refs/heads/main.tar.gz"
const updateCheckInterval = 30 /* Seconds */ * 1000
let oldSourceHash = null

// Deploys the new repository contents to ./live (which Docker will mount to esinko.net/live)
async function deploy(files){
    console.log("Deploying changes...")
    // Remove old version
    if(fs.existsSync("./live") && fs.statSync("./live").isDirectory()){
        fs.rmdirSync("./live", { recursive: true })
    }
    fs.mkdirSync("./live")

    // Write new files
    for(let file of files){
        // Only files supported. Links/Symlinks will be ignored.
        if(file.type == "file"){
            // Create directories if needed
            if(file.name.includes("/")){
                let dirs = file.name.split("/")
                dirs.pop()
                dirs = dirs.join("/")
                if(fs.existsSync("./live/" + dirs) && fs.statSync("./live/" + dirs).isDirectory());
                else {
                    fs.mkdirSync("./live/" + dirs, { recursive: true })
                }
                fs.writeFileSync("./live/" + file.name, file.data)
            }else {
                fs.writeFileSync("./live/" + file.name, file.data)
            }
        }
    }
    console.log("Changes deployed!")
}

// Tar magic
async function decodeHeader(data){
    // Decoding utility constants
    const vls = {
        zro_offset: "0".charCodeAt(0),
        types: {
            0: "file",
            1: "link",
            2: "symlink",
            3: "char",
            4: "block",
            5: "dir",
            6: "fifo",
            7: "con",
            72: "pax",
            55: "pax-global",
            27: "gnu-long-link-path",
            28: "gnu-long.path", // 28 & 30 are the same type!
            30: "gnu-long-path"
        },
        magic: {
            ustar: Buffer.from("ustar\x00", "binary"),
            gnu_magic: Buffer.from("ustar\x20", "binary"),
            gnu_ver: Buffer.from("\x20\x00", "binary"),
            offset: 257,
            version_off: 263
        }
    }

    // Utility functions
    const decode = {
        checkSum: async (blocks) => {
            let sum = 8 * 32
            for(let i = 0; i < 148; i++) sum += blocks[i]
            for(let ii = 156; ii < 512; ii++) sum += blocks[ii]
            return sum
        },
        find: async (block, number, offset, close) => {
            for(; offset < close; offset++) if(block[offset] === number) {
                return offset
            }
            return close
        },
        base256: async (buffer) => {
            // The first byte must be 80 or FF
            // 80 = positive, ff = 2's comp
            let positive;
            if(buffer[0] === 0x80) positive = true
            else if(buffer[0] === 0xFF) positive = false
            else return null

            // Build base256
            let tpl = []
            for(let i = buffer.length - 1; i > 0; i--){
                let byte = buffer[i]
                if(positive) tpl.push(byte)
                else tpl.push(0xFF - byte)
            }

            let sum = 0
            for(let byte of tpl){
                sum += byte * Math.pow(256, tpl.indexOf(byte))
            }

            return positive ? sum : -1 * sum
        },
        clmp: async (index, length, dflt) => {
            if(typeof index !== "number") return dflt
            index = ~~index
            if(index >= length) return length
            if(index >= 0) return index
            index += length
            if(index >= 0) return index
            return 0
        },
        oct: async (val, offset, length) => {
            val = val.slice(offset, offset + length)
            offset = 0

            // Is this a base256 integer
            if(val[offset] & 0x80){
                return await decode.base256(val)
            }else {
                // Older versions prefix with spaces
                while (offset < val.length && val[offset] === 32) ++offset
                let close = await decode.clmp(await decode.find(val, 32, offset, val.length), val.length, val.length)
                while (offset < close && val[offset] === 0) ++offset
                if(close === offset) return 0
                return parseInt(val.slice(offset, close).toString(), 8)
            }
        },
        str: async (val, offset, length) => {
            return val.slice(offset, await decode.find(val, 0, offset, offset + length)).toString()
        }
    }

    // Get POSIX header data
    let header = {
        name: await decode.str(data, 0, 100),
        mode: await decode.oct(data, 100, 8),
        uid: await decode.oct(data, 108, 8),
        gid: await decode.oct(data, 116, 8),
        size: await decode.oct(data, 124, 12),
        mtime: await decode.oct(data, 136, 12),
        type: vls.types[data[156] === 0 ? 0 : data[156] - vls.zro_offset],
        link_name: data[157] === 0 ? null : await decode.str(data, 157, 100),
        uname: await decode.str(data, 265, 32),
        gname: await decode.str(data, 297, 32),
        dev_major: await decode.oct(data, 329, 8),
        dev_minor: await decode.oct(data, 337, 8),
    }

    let checksum = await decode.checkSum(data)

    if (checksum === 8 * 32) return null // No global header, no valid data

    // Validate checksum
    if(checksum !== await decode.oct(data, 148, 8)) {
        // Check for a pax header
        try {
            let res = {}
            while(data.length) {
                let i = 0
                while (i < data.length && data[i] !== 32) i++
                let length = parseInt(data.slice(0, i).toString(), 10)
                if(!length) return res
                let entry = data.slice(i + 1, length -1).toString()
                let key = entry.indexOf("=")
                if(key === -1) return res
                res[entry.slice(0, key)] = entry.slice(key + 1)
                data = data.slice(length)
            }
            if(Object.keys(res).length === 0) throw "-"
            return res
        }
        catch(e){
            throw new Error("Tar data is corrupt or otherwise unreadable.")
        }
    }

    if(vls.magic.ustar.compare(data, vls.magic.offset, vls.magic.offset + 6) === 0){
        // POSIX format may want a prefix
        if(data[345]) header.name = await decode.str(data, 345, 155) + "/" + header.name
    }else if(vls.magic.gnu_magic.compare(data, vls.magic.offset, vls.magic.offset + 6) === 0 && vls.magic.gnu_ver.compare(data, vls.magic.version_off, vls.magic.version_off + 2) === 0){
        // Old GNU format.
        // Has support for multi-volume tarballs, but we are just going to ignore those cos I'm lazy
    }else {
        throw new Error("Unknown tar format.")
    }

    // Recognize trailing / that older versions use to indicate directories
    if(header.type === 0 && header.name != undefined && header.name[header.name.length - 1] === "/") header.type = 5

    return header
}

// Builds the source object
async function buildSourceObject(source){
    let hash = crypto.createHash("sha256").update(source).digest("hex")
    let files = []


    // Decompress data
    let decompressed = zlib.gunzipSync(source)

    // Parse global header
    let global_header = await decodeHeader(decompressed)
    decompressed = decompressed.slice(512)

    // Parse PAX header
    let pax_header = await decodeHeader(decompressed)
    decompressed = decompressed.slice(global_header.size)
    let offset = global_header.size &= 511
    offset = offset && 512 - offset
    decompressed = decompressed.slice(offset)

    // Parse entries
    let root = true
    let rootPrefix = ""
    let parseEntries = async () => {
        let header = await decodeHeader(decompressed)
        decompressed = decompressed.slice(512)

        // Handle root entry
        if(root){
            root = false
            rootPrefix = header.name
        }else {
            // Handle header
            if(header == null) {
                // No data
                return
            }else {
                // We have data to read
                if (header.type == "file") {
                    let data = decompressed.slice(0, header.size).toString()
                    files.push({ type: "file", name: header.name.replace(rootPrefix, ""), data })
                }
            }
        }

        // Remove entry data
        decompressed = decompressed.slice(header.size)

        // Handle offset
        let offset = header.size &= 511
        offset = offset && 512 - offset
        decompressed = decompressed.slice(offset)
        return await parseEntries()
    }
    await parseEntries()

    return { files, hash }
}

// Downloads the tar from Github
async function fetchSource(url, redirectLayer){
    return new Promise((resolve, reject) => {
        const request = https.request(url, res => {
            let ResponseBuffer = []
            res.on("data", data => {ResponseBuffer.push(data)})
            res.on("end", async () => {
                if(res.statusCode === 200){
                    // Success
                    let obj = await buildSourceObject(new Buffer.concat(ResponseBuffer))
                    resolve([obj.files, obj.hash])
                }else if(res.statusCode === 302){
                    if(redirectLayer != undefined){
                        if(redirectLayer > 5){
                            reject("Too many redirects.")
                            return
                        }
                        ++redirectLayer
                    }else {
                        redirectLayer = 0
                    }
                    fetchSource(res.headers.location, redirectLayer).then(source => {
                        resolve(source)
                    })
                }else {
                    // Failed
                    console.log("Failed to fetch page sources.", res.statusCode, ResponseBuffer)
                    resolve({ files: [{filename: "index.html", data: "<h1>Failed to fetch page source. Contact dev@esinko.net.</h1>"}], hash: "0"})
                }
            })
        })
        request.on("error", e => {
            reject(e)
        })
        request.end()
    })
}

// Timed action execution
async function TimedAction(){
    // Do what this script is supposed to do
    let source = await fetchSource(ZipLocation)
    // Check the hash
    // Compare sources
    if(oldSourceHash != source[1]){
        oldSourceHash = source[1]
        console.log("[", new Date().toDateString(), "]","Got update!")
        deploy(source[0])
    }else {
        console.log("[", new Date().toDateString(), "]","No update.")
    }
}

TimedAction()
setInterval(async () => {
    TimedAction()
}, updateCheckInterval)