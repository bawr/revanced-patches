package app.bawr.revanced.patches.signal

import app.revanced.patcher.extensions.InstructionExtensions.addInstruction
import app.revanced.patcher.fingerprint
import app.revanced.patcher.patch.bytecodePatch
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode

@Suppress("unused")
val signalPatch = bytecodePatch(
    name = "SignalKeep",
    description = "Don't remove expired messages.",
) {
    compatibleWith("org.thoughtcrime.securesms"("7.62.3"))

//  extendWith("extensions/extension.rve")

    execute {
        val loadTaskRunFingerprint = fingerprint {
            accessFlags(AccessFlags.PUBLIC)
            returns("V")
            parameters("V")
            opcodes(Opcode.RETURN_VOID)
            custom {
                methodDef, classDef -> (methodDef.name == "run") && (classDef.type == "Lorg/thoughtcrime/securesms/service/ExpiringMessageManager${'$'}LoadTask;")
            }
        }

        loadTaskRunFingerprint.method.addInstruction(
            0,
            "return-void",
        )
    }
}
