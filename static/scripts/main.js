var filenames = [];
var base_url = "http://localhost:5000/api"

const pAll = async (queue, concurrency) => {
    let index = 0;
    const results = [];
  
    // Run a pseudo-thread
    const execThread = async () => {
      while (index < queue.length) {
        const curIndex = index++;
        // Use of `curIndex` is important because `index` may change after await is resolved
        results[curIndex] = await queue[curIndex]();
      }
    };
  
    // Start threads
    const threads = [];
    for (let thread = 0; thread < concurrency; thread++) {
      threads.push(execThread());
    }
    await Promise.all(threads);
    return results;
};

function progress_bar(filename) {
    $('#upload-wrapper').hide();
    $('#status').append(
        $('<div>', { 'class': 'progress-bar-wrapper', 'data-filename': filename })
            .append($('<div>', { 'class': 'progress-bar-text px-0 py-2 very-small regular mt-2' })
                .append($('<span>', { 'class': '' }).html('Uploading '))
                .append($('<span>', { 'class': 'bold' }).html(filename))
                .append($('<span>', { 'class': '' }).html('...'))
            )
            .append($('<div>', { 'class': 'rounded bg-lightgrey border-custom overflow-hidden mb-3' })
                .append($('<div>', { 'class': 'progress-bar bg-primary text-center py-1 rounded-right text-nowrap' })
                    .html('0%')
                    .css('width', '0%')
                )
            )
    );
}

function range(n) {
    const R = []
    for (let i = 1; i < n+1; i++) R.push(i)
    return R
}

async function upload_chunk(chunk, uid, uuid, file, chunk_size) {
    var payload_part = {
        "filename": uuid+"/"+file['name'],
        "upload_id": uid,
        "part_number": chunk
    }
    const res_part = await fetch(base_url+'/signmultipart', 
    {   
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload_part)
    })
    const res_signed_part = await res_part.json();

    const resp = await fetch(res_signed_part["url"], 
    {   
        method: "PUT",
        body: file.slice((chunk-1)*chunk_size, Math.min(file.size, (chunk)*chunk_size)),
    })
    
    var etag = await resp.headers.get("etag").replaceAll("\"", "")
    return {"ETag": etag, "PartNumber": chunk}
}

// Upload Reads to Amazon S3 Bucket
function upload_file() {

    // Get files
    var files = $('#fileinput').prop('files'),
        oversized_files = [],
        files_with_space = [],
        wrong_format_files = [],
        gb_limit = 5;

    // Check file size
    $.each(files, function (index, file) {
        if (file.size > gb_limit * Math.pow(10, 9)) {
            oversized_files.push(file.name + ' (' + (file.size / Math.pow(10, 9)).toFixed(2) + ' GB)');
        }
        if (file.name.indexOf(' ') > -1) {
            files_with_space.push(file.name)
        }
    })

    // Check if any file is oversized
    if (oversized_files.length) {
        // Alert oversized files
        alert('The following files exceed ' + gb_limit + 'GB, which is the maximum file size supported by BioJupies. Please remove them to proceed.\n\n • ' + oversized_files.join('\n • ') + '\n\nTo analyze the data, we recommend quantifying gene counts using kallisto or STAR, and uploading the generated read counts using the BioJupies table upload (https://amp.pharm.mssm.edu/biojupies/upload).');
    } else if (files_with_space.length) {
        // Alert oversized files
        alert('The following file(s) contain one or more spaces in their file names. This is currently not supported by the BioJupies alignment pipeline. Please rename them to proceed.\n\n • ' + files_with_space.join('\n • '));
    } else if (wrong_format_files.length) {
        // Alert wrong format files
        alert('BioJupies only supports alignment of files in the .fastq.gz or .fq.gz formats. The following file(s) are stored in formats which are currently not supported. Please remove or reformat them to proceed.\n\n • ' + wrong_format_files.join('\n • '));
    } else {
        // Loop through files
        $.each(files, function (index, file) {
            if (file.size < 10 * 1024 * 1024) {
                (async() => {
                    const response = await fetch(base_url+'/upload', 
                    {
                        method: "POST",
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify ({"filename": file['name']})
                    })
                    const data = await response.json();
                    var formdata = new FormData();
                    for (var key in data["response"]["fields"]) {
                        formdata.append(key, data["response"]["fields"][key]);
                    }
                    formdata.append('file', file);
                    
                    fetch(data["response"]["url"], 
                    {
                        method: "POST",
                        body: formdata
                    })
                })(); // end async

            } // simple file upload
            else {
                var chunk_size = 6*1024*1024;
                var chunk_number = file.size/chunk_size;
                var chunks = range(chunk_number);

                var payload = JSON.stringify({
                    "filename": file['name']
                });

                (async() => {
                    const response = await fetch(base_url+'/startmultipart', 
                    {
                        method: "POST",
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        body: payload
                    })
                    const res = await response.json();

                    const values = await pAll(
                        chunks.map(chunk => () => upload_chunk(chunk, res["upload_id"], res["uuid"], file, chunk_size)),
                        4
                    );
                    
                    var payload_complete = {
                        "filename": res["uuid"]+"/"+file['name'],
                        "upload_id": res["upload_id"],
                        "parts": values
                    }
                    
                    fetch(base_url+"/completemultipart", {
                        method: "POST",
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(payload_complete)
                    }) // end complete

                })(); // end async
            }
        })
    }
}
