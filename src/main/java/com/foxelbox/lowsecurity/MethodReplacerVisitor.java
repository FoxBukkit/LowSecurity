package com.foxelbox.lowsecurity;

import org.objectweb.asm.*;

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
