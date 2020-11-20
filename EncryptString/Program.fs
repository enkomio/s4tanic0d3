open System
open System.Reflection
open System.Text
open System.IO

let rc4(key: Byte array, data: Byte array) =
    let mutable S = [|for i in 0 .. 255 -> i|]

    // KSA
    let mutable j =0
    for i in 0..255 do
        j <- (j + S.[i] + int32(key.[i % key.Length])) % 256
        let mutable tmp = S.[i]
        S.[i] <- S.[j]
        S.[j] <- tmp

    // PRGA
    let mutable i = 0
    let mutable j = 0
    let result = Array.zeroCreate<Byte>(data.Length)

    data
    |> Array.iteri(fun index b ->
        i <- (i + 1) % 256
        j <- (j + S.[i]) % 256

        // swap
        let mutable tmp = S.[i]
        S.[i] <- S.[j]
        S.[j] <- tmp

        let k = S.[(S.[i] + S.[j]) % 256]
        data.[index] <- data.[index] ^^^ byte k
    )  


[<EntryPoint>]
let main argv =
    let key = [|0xdeuy; 0xc0uy; 0x7auy; 0x5auy|]
    let greeting = """License valid!
    
            -=[ s4tanicod3 ]=-
    
        BEING THE WISE AND COURAGEOUR
    
          KNIGHT THAT YOU ARE YOU
    
           FEEL STRONGTH WELLING
    
               IN YOUR BODY.
    
           Thank you for playing!
    
        --
        (c) enkomio - 2020
        https://github.com/enkomio/s4tanic0d3
     """

    let musicFileContent = 
        Path.Combine(
            Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), 
            "BeepBox-Song.wav"
        )
        |> Path.GetFullPath
        |> File.ReadAllBytes    

    // encrypt
    rc4(key, musicFileContent)
    let encGreeting = Encoding.ASCII.GetBytes(greeting)
    encGreeting.[encGreeting.Length - 1] <- 0uy
    rc4(key, encGreeting)
    
    // create file content
    let res = new StringBuilder()
    let mutable name = "g_sound "
    musicFileContent
    |> Array.chunkBySize 16
    |> Array.iteri(fun i chunk -> 
        res.AppendFormat("{0}byte ", name) |> ignore
        name <- String.Empty
        let t = new StringBuilder()
        chunk
        |> Array.iter(fun b ->
            let s = String.Format("0{0}h, ", b.ToString("X"))
            t.Append(s) |> ignore
        )

        res.AppendLine(t.ToString().Trim().Trim(',')) |> ignore
    )

    res.AppendFormat("g_sound_size dword 0{0}h", musicFileContent.Length.ToString("X")) |> ignore
    res.AppendLine() |> ignore

    name <- "g_success "
    encGreeting
    |> Array.chunkBySize 16
    |> Array.iteri(fun i chunk -> 
        res.AppendFormat("{0}byte ", name) |> ignore
        name <- String.Empty
        let t = new StringBuilder()
        chunk
        |> Array.iter(fun b ->
            let s = String.Format("0{0}h, ", b.ToString("X"))
            t.Append(s) |> ignore
        )

        res.AppendLine(t.ToString().Trim().Trim(',')) |> ignore
    )

    res.AppendLine() |> ignore
    res.AppendFormat("g_success_size dword 0{0}h", (encGreeting.Length - 1).ToString("X")) |> ignore
    
    // write file
    let resultFile =
        Path.Combine(
            Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), 
            "..", 
            "..", 
            "..", 
            "..",
            "Src",
            "media.inc"
        )
        |> Path.GetFullPath
    File.WriteAllText(resultFile, res.ToString())
    0
