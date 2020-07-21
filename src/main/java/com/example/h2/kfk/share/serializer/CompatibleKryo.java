package com.example.h2.kfk.share.serializer;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.serializers.JavaSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CompatibleKryo extends Kryo {
    private static final Logger logger = LoggerFactory.getLogger(CompatibleKryo.class);

    public CompatibleKryo() {
    }

    @Override
    public Serializer getDefaultSerializer(Class type) {
        if (type == null) {
            throw new IllegalArgumentException("type cannot be null.");
        } else if (!type.isArray() && !this.checkZeroArgConstructor(type)) {
            if (logger.isDebugEnabled()) {
                logger.debug("{} has no zero-arg constructor and this will affect the serialization performance", type);
            }

            return new JavaSerializer();
        } else {
            return super.getDefaultSerializer(type);
        }
    }

    private boolean checkZeroArgConstructor(Class<?> clazz) {
        try {
            clazz.getDeclaredConstructor();
            return true;
        } catch (NoSuchMethodException var3) {
            logger.debug("Cannot find getDeclaredConstructor method for class [{}]", clazz);
            return false;
        }
    }
}
