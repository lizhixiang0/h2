package com.example.h2.kfk.share.serializer;//

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.KryoException;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import com.esotericsoftware.kryo.pool.KryoPool;
import com.esotericsoftware.kryo.pool.KryoPool.Builder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class KryoSerializer {
    private static final Logger logger = LoggerFactory.getLogger(KryoSerializer.class);
    public static KryoSerializer INSTANCE = new KryoSerializer();
    private final KryoPool pool = (new Builder(() -> {
        return this.buildKryo();
    })).softReferences().build();

    private KryoSerializer() {
    }

    private Kryo buildKryo() {
        Kryo kryo = new CompatibleKryo();
        kryo.setReferences(false);
        kryo.setRegistrationRequired(false);
        return kryo;
    }

    public byte[] serialize(Object t) {
        if (t == null) {
            return null;
        } else {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Output output = new Output(baos);
            Kryo kryo = this.pool.borrow();

            byte[] var5;
            try {
                kryo.writeClassAndObject(output, t);
                output.close();
                var5 = baos.toByteArray();
            } finally {
                this.pool.release(kryo);
            }

            return var5;
        }
    }

    public Object deserialize(byte[] bytes) {
        if (bytes != null && bytes.length != 0) {
            Input input = new Input(new ByteArrayInputStream(bytes));
            Kryo kryo = this.pool.borrow();

            DeserializeFailedResult var5;
            try {
                Object obj = kryo.readClassAndObject(input);
                logger.trace("Deserialize bytes [size={}] to class [{}].", bytes.length, obj.getClass().getName());
                Object var15 = obj;
                return var15;
            } catch (KryoException var11) {
                logger.warn("KryoSerializer.deserialize hitting KryoException, cannot deserialize requested byte[], just return DeserializeFailedResult object instead...", var11);
                var5 = new DeserializeFailedResult();
                return var5;
            } catch (Exception var12) {
                logger.warn("KryoSerializer.deserialize hitting Exception, cannot deserialize requested byte[], just return DeserializeFailedResult object instead...", var12);
                var5 = new DeserializeFailedResult();
            } catch (Error var13) {
                logger.warn("KryoSerializer.deserialize hitting Error, cannot deserialize requested byte[], size={}, just return DeserializeFailedResult object instead...", bytes.length, var13);
                var5 = new DeserializeFailedResult();
                return var5;
            } finally {
                this.pool.release(kryo);
                input.close();
            }

            return var5;
        } else {
            return null;
        }
    }
}
