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

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.TypePath;

public abstract class MethodReplacerVisitor extends MethodVisitor {
    protected final MethodVisitor mv;

    public MethodReplacerVisitor(int api, MethodVisitor methodVisitor) {
        super(api);
        mv = methodVisitor;
    }

    @Override
    public void visitParameter(String s, int i) {
        mv.visitParameter(s, i);
    }

    @Override
    public AnnotationVisitor visitAnnotation(String s, boolean b) {
        return mv.visitAnnotation(s, b);
    }

    @Override
    public AnnotationVisitor visitAnnotationDefault() {
        return mv.visitAnnotationDefault();
    }

    @Override
    public AnnotationVisitor visitTypeAnnotation(int i, TypePath typePath, String s, boolean b) {
        return mv.visitTypeAnnotation(i, typePath, s, b);
    }

    @Override
    public AnnotationVisitor visitParameterAnnotation(int i, String s, boolean b) {
        return mv.visitParameterAnnotation(i, s, b);
    }

    @Override
    public void visitAttribute(Attribute attribute) {
        mv.visitAttribute(attribute);
    }

    @Override
    public void visitCode() {
        mv.visitCode();
        writeCode();
    }

    public abstract void writeCode();

    @Override
    public void visitEnd() {
        mv.visitEnd();
    }
}
