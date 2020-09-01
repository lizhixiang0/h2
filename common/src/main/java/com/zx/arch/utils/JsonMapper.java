package com.zx.arch.utils;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonParser.Feature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.util.JSONPObject;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JsonMapper extends ObjectMapper {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(JsonMapper.class);
    private static JsonMapper mapper;

    public JsonMapper() {
        this(Include.NON_EMPTY);
    }

    public JsonMapper(Include include) {
        if (include != null) {
            this.setSerializationInclusion(include);
        }

        this.enableSimple();
        this.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        this.getSerializerProvider().setNullValueSerializer(new JsonSerializer<Object>() {
            public void serialize(Object value, JsonGenerator jgen, SerializerProvider provider) throws IOException {
                jgen.writeString("");
            }
        });
        this.registerModule((new SimpleModule()).addSerializer(String.class, new JsonSerializer<String>() {
            public void serialize(String value, JsonGenerator jgen, SerializerProvider provider) throws IOException {
                jgen.writeString(StringEscapeUtils.unescapeHtml4(value));
            }
        }));
        this.setTimeZone(TimeZone.getDefault());
    }

    public static JsonMapper nonEmptyMapper() {
        return new JsonMapper(Include.NON_EMPTY);
    }

    public static JsonMapper nonDefaultMapper() {
        if (mapper == null) {
            mapper = new JsonMapper(Include.NON_DEFAULT);
        }

        return mapper;
    }

    public String toJson(Object object) {
        try {
            return this.writeValueAsString(object);
        } catch (IOException var3) {
            logger.warn("write to json string error:" + object, var3);
            return null;
        }
    }

    public static JsonMapper getInstance() {
        if (mapper == null) {
            mapper = (new JsonMapper()).enableSimple();
        }

        return mapper;
    }

    public <T> T fromJson(String jsonString, Class<T> clazz) {
        if (StringUtils.isBlank(jsonString)) {
            return null;
        } else if (StringUtils.equals("\"\"", jsonString)) {
            return null;
        } else {
            try {
                return this.readValue(jsonString, clazz);
            } catch (IOException var4) {
                return null;
            }
        }
    }

    public <T> T fromJson(String jsonString, JavaType javaType) {
        if (StringUtils.isEmpty(jsonString)) {
            return null;
        } else if (StringUtils.equals("\"\"", jsonString)) {
            return null;
        } else {
            try {
                return this.readValue(jsonString, javaType);
            } catch (IOException var4) {
                return null;
            }
        }
    }

    public JavaType createCollectionType(Class<?> collectionClass, Class<?>... elementClasses) {
        return mapper.getTypeFactory().constructParametrizedType(collectionClass, collectionClass, elementClasses);
    }

    public <T> T update(String jsonString, T object) {
        try {
            return this.readerForUpdating(object).readValue(jsonString);
        } catch (JsonProcessingException var4) {
            logger.warn("update json string:" + jsonString + " to object:" + object + " error.", var4);
        } catch (IOException var5) {
            logger.warn("update json string:" + jsonString + " to object:" + object + " error.", var5);
        }

        return null;
    }

    public String toJsonP(String functionName, Object object) {
        return this.toJson(new JSONPObject(functionName, object));
    }

    public JsonMapper enableEnumUseToString() {
        this.enable(SerializationFeature.WRITE_ENUMS_USING_TO_STRING);
        this.enable(DeserializationFeature.READ_ENUMS_USING_TO_STRING);
        return this;
    }

    public JsonMapper enableJaxbAnnotation() {
        JaxbAnnotationModule module = new JaxbAnnotationModule();
        this.registerModule(module);
        return this;
    }

    public JsonMapper enableSimple() {
        this.configure(Feature.ALLOW_SINGLE_QUOTES, true);
        this.configure(Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
        return this;
    }

    public ObjectMapper getMapper() {
        return this;
    }

    public static String toJsonString(Object object) {
        return getInstance().toJson(object);
    }

    public static <T> T fromJsonString(String jsonString, Class<T> clazz) {
        return getInstance().fromJson(jsonString, clazz);
    }

    public static <T> T fromJsonString(String jsonString, JavaType javaType) {
        return getInstance().fromJson(jsonString, javaType);
    }

    public static Map<String, String> fromJsonString(String jsonString) {
        return (Map)getInstance().fromJson(jsonString, getInstance().createCollectionType(Map.class, String.class, String.class));
    }

    public static boolean isJsonValue(String value) {
        return getInstance().fromJson(value, getInstance().createCollectionType(Map.class, String.class, Object.class)) != null || fromJsonString(value, getInstance().createCollectionType(List.class, Object.class)) != null;
    }
}
