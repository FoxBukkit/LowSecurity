package com.foxelbox.lowsecurity;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;

public interface MyClassFileTransformer extends ClassFileTransformer {
    void patch(final Instrumentation instrumentation);
}
