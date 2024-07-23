//
//  upload.swift
//  Hermes
//
//  Created by Justin Bui on 6/21/21.
//

import Foundation

func upload(job: Job) {
    do {
        if job.uploadTotalChunks == 1 {
            try fromBase64(data: job.uploadData).write(to: URL(fileURLWithPath: job.uploadFullPath))
            job.result = "Upload of \(job.uploadFullPath) complete"
            job.completed = true
            job.success = true
        }
        else if job.uploadTotalChunks > 1 && (job.uploadChunkNumber <= job.uploadTotalChunks) {
            let fileManager = FileManager.default
            let decodedData = fromBase64(data: job.uploadData)
            //print("Chunk num: " + String(job.uploadChunkNumber))
            //print(decodedData.count)

            if job.uploadChunkNumber == 1 {
                if fileManager.fileExists(atPath: job.uploadFullPath) {
                    let fileURL = URL(fileURLWithPath: job.uploadFullPath)
                    try FileManager.default.removeItem(at: fileURL)
                }
                
                fileManager.createFile(atPath: job.uploadFullPath, contents: decodedData, attributes: nil)
            }
            else {
                let fileHandle = FileHandle(forWritingAtPath: job.uploadFullPath)
                fileHandle?.seekToEndOfFile()
                fileHandle?.write(decodedData)
                fileHandle?.closeFile()
                if job.uploadTotalChunks == job.uploadChunkNumber {
                    job.result = "Upload of \(job.uploadFullPath) complete"
                    job.completed = true
                    job.success = true
                }
            }
        }
    }
    catch {
        job.result = "Exception caught: \(error)"
        job.completed = true
        job.success = false
        job.status = "error"
    }
}
