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
package com.foxelbox.lowsecurity;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class LowSecurityPremain implements ClassFileTransformer {
    public static void premain(String agentArgument, final Instrumentation instrumentation) {
        System.out.println("Hotpatching :)");
        LowSecurityPremain transformer = new LowSecurityPremain();
        instrumentation.addTransformer(transformer, true);
        try {
            instrumentation.retransformClasses(System.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
        instrumentation.removeTransformer(transformer);
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if(className.equals("java/lang/System")) {
            ClassReader classReader = new ClassReader(classfileBuffer);
            ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS);
            LowSecurityClassVisitor lowSecurityClassVisitor = new LowSecurityClassVisitor(classWriter);
            classReader.accept(lowSecurityClassVisitor, 0);
            return classWriter.toByteArray();
        }
        return classfileBuffer;
    }
}
