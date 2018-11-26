package ntldd

@ExperimentalUnsignedTypes
fun main(args: Array<String>) {
    args.forEach {
        DllTree(it, listOf("C:\\msys64\\mingw64\\bin")).print()
    }
}
