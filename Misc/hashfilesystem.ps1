Get-ChildItem 'C:\' -File -Recurse -PipelineVariable File | ForEach-Object {
       
    $stream = try {
        [IO.FileStream]::new( $File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read )
    }
    catch {
        # Fallback in case another process has opened the file with FileShare.ReadWrite flag.
        [IO.FileStream]::new( $File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite )
    }

    if( $stream ) {
        try {
            Get-FileHash -InputStream $stream -Algorithm SHA256 
                Select-Object Algorithm, Hash, @{ Name = 'Path'; Expression = { $File.Fullname } }
        }
        finally {
            $stream.Close() 

        }
    }
}

#SHA1
#SHA256
#SHA384
#SHA512
#MACTripleDES
#MD5
#RIPEMD160