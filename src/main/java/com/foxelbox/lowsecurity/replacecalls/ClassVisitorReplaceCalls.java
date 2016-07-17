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
package com.foxelbox.lowsecurity.replacecalls;

import com.foxelbox.lowsecurity.MyClassFileTransformer;
import org.objectweb.asm.*;

import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;

public class ClassVisitorReplaceCalls extends ClassVisitor {
    public static class ClassTransformer implements MyClassFileTransformer {
        private static final String LOW_SECURITY_SYSTEM_CLASS = LowSecuritySystem.class.getName().replace('.', '/');
        private static byte[] LOW_SECURITY_SYSTEM_BYTES = null;

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
            if(LOW_SECURITY_SYSTEM_BYTES == null && className.equals(LOW_SECURITY_SYSTEM_CLASS)) {
                LOW_SECURITY_SYSTEM_BYTES = classfileBuffer;
                return classfileBuffer;
            }

            if(loader != null && !className.startsWith("java/") && !className.startsWith("com/sun/") && !className.startsWith("jdk/") && !className.startsWith("com/foxelbox/lowsecurity/") && !className.startsWith("javax/") && !className.startsWith("sun/")) {
                try {
                    loader.loadClass(LOW_SECURITY_SYSTEM_CLASS.replace('/', '.'));
                } catch (Exception e) {
                    System.err.println("ClassLoader does not know LowSecuritySystem");
                    try {
                        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                        defineClass.setAccessible(true);
                        defineClass.invoke(loader, LOW_SECURITY_SYSTEM_BYTES, 0, LOW_SECURITY_SYSTEM_BYTES.length);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }

                ClassReader classReader = new ClassReader(classfileBuffer);
                ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                ClassVisitorReplaceCalls lowSecurityClassVisitorPatchSystem = new ClassVisitorReplaceCalls(classWriter, className);
                classReader.accept(lowSecurityClassVisitorPatchSystem, 0);
                return classWriter.toByteArray();
            }

            return classfileBuffer;
        }

        @Override
        public void patch(Instrumentation instrumentation) {
            try {
                instrumentation.addTransformer(this, true);
                instrumentation.retransformClasses(LowSecuritySystem.class);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private final String className;

    public ClassVisitorReplaceCalls(ClassVisitor classVisitor, String className) {
        super(Opcodes.ASM5, classVisitor);
        this.className = className;
    }

    private class MethodCallReplacerVisitor extends MethodVisitor {
        private final int access;
        private final String methodName;
        private final String methodDesc;
        private final String signature;
        private final String[] exceptions;

        public MethodCallReplacerVisitor(int api, MethodVisitor methodVisitor, int access, String methodName, String methodDesc, String signature, String[] exceptions) {
            super(api, methodVisitor);
            this.access = access;
            this.methodName = methodName;
            this.methodDesc = methodDesc;
            this.signature = signature;
            this.exceptions = exceptions;
        }

        private boolean checkMethodInsn(int opcode, String clazz, String name, String desc) {
            if(opcode != Opcodes.INVOKESTATIC) {
                return true;
            }
            if(!clazz.equals("java/lang/System")) {
                return true;
            }
            switch(name) {
                case "setSecurityManager":
                    System.out.println("Patching setSecurityManager call in " + className + "." + methodName);
                    super.visitMethodInsn(opcode, "com/foxelbox/lowsecurity/replacecalls/LowSecuritySystem", name, desc, false);
                    return false;
                case "getSecurityManager":
                    System.out.println("Patching getSecurityManager call in " + className + "." + methodName);
                    super.visitMethodInsn(opcode, "com/foxelbox/lowsecurity/replacecalls/LowSecuritySystem", name, desc, false);
                    return false;
            }
            return true;
        }

        @Override
        public void visitMethodInsn(int opcode, String clazz, String name, String desc, boolean isInterface) {
            if(checkMethodInsn(opcode, clazz, name, desc)) {
                super.visitMethodInsn(opcode, clazz, name, desc, isInterface);
            }
        }

        @Override
        public void visitMethodInsn(int opcode, String clazz, String name, String desc) {
            if(checkMethodInsn(opcode, clazz, name, desc)) {
                super.visitMethodInsn(opcode, clazz, name, desc);
            }
        }
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        return new MethodCallReplacerVisitor(api, super.visitMethod(access, name, desc, signature, exceptions), access, name, desc, signature, exceptions);
    }
}
