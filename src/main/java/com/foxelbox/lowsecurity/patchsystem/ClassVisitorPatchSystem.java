/**
 * This file is part of LowSecurity.
 *
 * LowSecurity is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LowSecurity is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LowSecurity.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.foxelbox.lowsecurity.patchsystem;

import com.foxelbox.lowsecurity.MethodReplacerVisitor;
import com.foxelbox.lowsecurity.MyClassFileTransformer;
import org.objectweb.asm.*;

import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class ClassVisitorPatchSystem extends ClassVisitor {
    public static class ClassTransformer implements MyClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
            if(className.equals("java/lang/System")) {
                ClassReader classReader = new ClassReader(classfileBuffer);
                ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                ClassVisitorPatchSystem classVisitorPatchSystem = new ClassVisitorPatchSystem(classWriter);
                classReader.accept(classVisitorPatchSystem, 0);
                return classWriter.toByteArray();
            }
            return classfileBuffer;
        }

        @Override
        public void patch(Instrumentation instrumentation) {
            instrumentation.addTransformer(this, true);
            try {
                instrumentation.retransformClasses(System.class);
            } catch (Exception e) {
                e.printStackTrace();
            }
            instrumentation.removeTransformer(this);
        }
    }

    public ClassVisitorPatchSystem(ClassVisitor classVisitor) {
        super(Opcodes.ASM5, classVisitor);
    }

    private static class LowSecurityMethodReplacer extends MethodReplacerVisitor {
        public LowSecurityMethodReplacer(int api, MethodVisitor methodVisitor) {
            super(api, methodVisitor);
        }

        @Override
        public void writeCode() {
            mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");

            mv.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
            mv.visitInsn(Opcodes.DUP);
            mv.visitLdcInsn("Prevented setting SecurityManager: ");
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);

            mv.visitVarInsn(Opcodes.ALOAD, 0);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/SecurityManager", "toString", "()Ljava/lang/String;", false);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);

            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);

            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);

            mv.visitInsn(Opcodes.RETURN);
        }
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
        if(name.equals("setSecurityManager")) {
            return new LowSecurityMethodReplacer(api, mv);
        }
        return mv;
    }
}
