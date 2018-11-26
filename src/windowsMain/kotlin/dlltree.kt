package ntldd

import kotlinx.cinterop.*
import platform.windows.*
import platform.windows.imagehlp.*

@ExperimentalUnsignedTypes
class DllTree(
    name: String,
    val path: List<String>
) {
    var arch = -1
    val root = Node(name)
    init {
        root.BuildTree()
    }

    inner class Node(
        val module: String
    ) {
        var resolved_module: String? = null
        var mapped_address: COpaquePointer? = null
        val childs = mutableListOf<Node>()
        var visited = false
        var unresolved = false
        var processed = false
    }

    fun Node.BuildTree(): Boolean = memScoped {
        if (processed) return true

        val img = alloc<_LOADED_IMAGE>()
        fun TryMapAndLoad(path: String?): Boolean {
            val succeed= MapAndLoad(module, path, img.ptr, TRUE, TRUE) == TRUE
            if (succeed && arch != -1 && img.FileHeader!!.pointed.FileHeader.Machine.toInt() != arch) {
                UnMapAndLoad(img.ptr)
                return false
            }
            return succeed
        }

        var loaded = false
        path.forEach {
            loaded = TryMapAndLoad(it)
            if (loaded) return@forEach
        }
        if (!loaded) {
            unresolved = true
            return false
        }

        if (arch == -1)
            arch = img.FileHeader!!.pointed.FileHeader.Machine.toInt()

        resolved_module = img.ModuleName?.toKString()
        mapped_address = img.MappedAddress
        processed = true

        data class Section(
            val start: DWORD,
            val end: DWORD,
            val ptr: CPointer<ByteVar>?
        )

        val sections = List<Section>(img.NumberOfSections.toInt()) { i ->
            val section = img.Sections!![i]
            Section(
                start = section.VirtualAddress,
                end = section.VirtualAddress + section.Misc.VirtualSize,
                ptr = if (section.PointerToRawData == 0U) null else (
                    img.MappedAddress.toLong()
                        + section.PointerToRawData.toLong()
                        - section.VirtualAddress.toLong()
                    ).toCPointer()
            )
        }

        fun MapPointer(addr: DWORD): CPointer<ByteVar>? {
            sections.forEach {
                if (addr in (it.start..it.end) && it.ptr != null)
                    return (it.ptr.toLong() + addr.toLong()).toCPointer()
            }
            return null
        }

        fun Node.FindDll(name: String): Node? {
            childs.forEach {
                if (it.module.equals(name, ignoreCase = true))
                    return it
            }
            childs.forEach {
                val dll = it.FindDll(name)
                if (dll != null)
                    return dll
            }
            return null
        }

        fun Node.ProcessDll(addr: DWORD): Node? {
            val name = MapPointer(addr)?.toKString() ?: return null
            return root.FindDll(name) ?: run {
                Node(name).also { childs.add(it) }
            }.also {
                it.BuildTree()
            }
        }

        fun DirEntry(entryType: Int): IMAGE_DATA_DIRECTORY {
            val opt_header = img.FileHeader!!.pointed.OptionalHeader.ptr
            return if (arch == IMAGE_FILE_MACHINE_I386)
                opt_header.reinterpret<IMAGE_OPTIONAL_HEADER32>().pointed.DataDirectory[entryType]
            else
                opt_header.reinterpret<IMAGE_OPTIONAL_HEADER64>().pointed.DataDirectory[entryType]
        }

        DirEntry(IMAGE_DIRECTORY_ENTRY_IMPORT).let {
            if (it.Size > 0U && it.VirtualAddress != 0U) {
                MapPointer(it.VirtualAddress)?.reinterpret<IMAGE_IMPORT_DESCRIPTOR>()?.let {
                    var i = 0
                    while (it[i].Name != 0U) {
                        ProcessDll(it[i].Name)
                        i++
                    }
                }
            }
        }

        DirEntry(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT).let {
            if (it.Size > 0U && it.VirtualAddress != 0U) {
                MapPointer(it.VirtualAddress)?.reinterpret<IMAGE_DELAYLOAD_DESCRIPTOR>()?.let {
                    var i = 0
                    while (it[i].DllNameRVA != 0U) {
                        ProcessDll(it[i].DllNameRVA)
                        i++
                    }
                }
            }
        }

        UnMapAndLoad(img.ptr)

        return true
    }

    fun Node.print() {
        if (unresolved || visited)
            return
        visited = true
        println(resolved_module)
        childs.forEach { it.print() }
    }

    fun print() {
        root.childs.forEach { it.print() }
    }
}
