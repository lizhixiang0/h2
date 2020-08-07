package com.zx.arch.config;

import com.zx.arch.kfk.share.serializer.KryoObjDeserializer;
import com.zx.arch.kfk.share.serializer.MsgSizeLoggedStringDeserializer;
import com.zx.arch.kfk.share.topic.TopicBeanProvider;
import org.apache.commons.lang3.StringUtils;
import org.apache.kafka.clients.ClientDnsLookup;
import org.apache.kafka.clients.ClientUtils;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.OffsetCommitCallback;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.IntegerDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.listener.ConsumerAwareRebalanceListener;
import org.springframework.kafka.listener.ContainerProperties.AckMode;

import java.util.*;

/**
 * @author admin
 */
@Configuration
public class ConsumerListenerContainerFactoryInitializer implements BeanDefinitionRegistryPostProcessor, ApplicationContextAware {
    private static final Logger log = LoggerFactory.getLogger(ConsumerListenerContainerFactoryInitializer.class);
    private Map<String, TopicBeanProvider> topicBeanProviderMap;
    protected static final int DEFAULT_CONCURRENCY = 1;
    protected Environment springEnvironment;
    protected String brokerHosts;
    protected boolean enableAutoCommit;
    protected int autoCommitIntervalMills;
    protected int defaultSessionTimeoutMills;
    protected int consumerContainerPollTimeoutMills;
    protected int defaultMaxPollRecords;
    protected int defaultMaxPollIntervalMills;
    protected boolean isSingleHostMode = false;

    public ConsumerListenerContainerFactoryInitializer() {
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.topicBeanProviderMap = applicationContext.getBeansOfType(TopicBeanProvider.class);
        this.springEnvironment = applicationContext.getEnvironment();
        this.brokerHosts = this.springEnvironment.getProperty("kafka.broker.hosts");
        if (StringUtils.isBlank(this.brokerHosts)) {
            throw new IllegalArgumentException("kafka.broker.hosts is mandatory, please config it in mq.properties");
        } else {
            this.enableAutoCommit = (Boolean)this.springEnvironment.getProperty("kafka.consumer.auto-commit", Boolean.class, Boolean.TRUE);
            this.autoCommitIntervalMills = (Integer)this.springEnvironment.getProperty("kafka.consumer.auto-commit-interval-ms", Integer.class, 100);
            this.defaultSessionTimeoutMills = (Integer)this.springEnvironment.getProperty("kafka.consumer.session-timeout-ms", Integer.class, 15000);
            this.consumerContainerPollTimeoutMills = (Integer)this.springEnvironment.getProperty("kafka.consumer.container-poll-timeout-ms", Integer.class, 3000);
            this.defaultMaxPollRecords = (Integer)this.springEnvironment.getProperty("kafka.consumer.max-poll-records", Integer.class, 100);
            this.defaultMaxPollIntervalMills = (Integer)this.springEnvironment.getProperty("kafka.consumer.max-poll-interval-ms", Integer.class, 3000);
            this.isSingleHostMode = this.resolveIfSingleHostMode(this.brokerHosts);
            if (this.isSingleHostMode) {
                log.info("Only 1 kafka broker host configured, all consumer concurrency values will be same as topic's partition number");
            }
        }
    }

    private boolean resolveIfSingleHostMode(String brokerHosts) {
        if (!brokerHosts.contains(",")) {
            return true;
        } else {
            try {
                return ClientUtils.parseAndValidateAddresses(Arrays.asList(brokerHosts.split(",")), ClientDnsLookup.DEFAULT).size() == 1;
            } catch (Exception var3) {
                throw new IllegalArgumentException("kafka.broker.hosts is invalid, please check it in mq.properties", var3);
            }
        }
    }

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
        Iterator beanNameIter = this.topicBeanProviderMap.keySet().iterator();

        while(true) {
            while(beanNameIter.hasNext()) {
                String topicBeanProviderName = (String)beanNameIter.next();
                log.info("Initializing topic bean by configuration[{}]", topicBeanProviderName);
                TopicBeanProvider topicBeanProvider = (TopicBeanProvider)this.topicBeanProviderMap.get(topicBeanProviderName);
                List<String> topicNames = topicBeanProvider.getTopicNames();
                if (topicNames != null && !topicNames.isEmpty()) {
                    Iterator var6 = topicNames.iterator();

                    while(var6.hasNext()) {
                        String topicName = (String)var6.next();
                        BeanDefinitionBuilder defBuilder = BeanDefinitionBuilder.genericBeanDefinition(ConcurrentKafkaListenerContainerFactory.class);
                        defBuilder.addPropertyValue("consumerFactory", this.consumerFactory(topicBeanProvider, topicName));
                        defBuilder.addPropertyValue("containerProperties.consumerTaskExecutor", new SimpleAsyncTaskExecutor(String.format("KafkaConsumer#%s#", topicName)));
                        defBuilder.addPropertyValue("containerProperties.pollTimeout", this.consumerContainerPollTimeoutMills);
                        AckMode ackMode = this.resolveAckMode(topicName);
                        if (ackMode != null) {
                            defBuilder.addPropertyValue("containerProperties.ackMode", ackMode);
                        }
                        defBuilder.addPropertyValue("batchListener", this.resolveBatchListener(topicName));
                        int concurrency = this.resolveConcurrency(topicName);
                        defBuilder.addPropertyValue("concurrency", concurrency);
                        this.initCallbackAndListener(defBuilder, topicName);
                        String topicContainerFactoryBeanName = topicName + topicBeanProvider.getConsumerContainerFactoryBeanSuffix();
                        registry.registerBeanDefinition(topicContainerFactoryBeanName, defBuilder.getBeanDefinition());
                        log.info("Registered Kafka consumer listener factory bean with name: {}, concurrency={}", topicContainerFactoryBeanName, concurrency);
                    }
                } else {
                    log.warn("No valid topic name specified.");
                }
            }

            return;
        }
    }

    private void initCallbackAndListener(BeanDefinitionBuilder defBuilder, String topicName) {
        //回调函数，记录提交错误
        defBuilder.addPropertyValue("containerProperties.commitCallback", (OffsetCommitCallback) (offsets, exception) -> {
            if (exception != null) {
                log.error("OffsetCommitCallback: Commit offset({}) failed for topic[{}]", new Object[]{offsets, topicName, exception});
            } else if (log.isDebugEnabled()) {
                log.debug("OffsetCommitCallback: Commit offset({}) success for topic[{}]", offsets, topicName);
            }
        });

        defBuilder.addPropertyValue("containerProperties.consumerRebalanceListener", new ConsumerAwareRebalanceListener() {
            @Override
            public void onPartitionsAssigned(Consumer<?, ?> consumer, Collection<TopicPartition> partitions) {
                if (ConsumerListenerContainerFactoryInitializer.log.isDebugEnabled()) {
                    ConsumerListenerContainerFactoryInitializer.log.debug("ConsumerAwareRebalanceListener: Topic[{}] partitions[{}] Assigned to consumer[{}]", new Object[]{topicName, partitions, consumer});
                }
            }

            @Override
            public void onPartitionsRevokedBeforeCommit(Consumer<?, ?> consumer, Collection<TopicPartition> partitions) {
                if (ConsumerListenerContainerFactoryInitializer.log.isDebugEnabled()) {
                    ConsumerListenerContainerFactoryInitializer.log.debug("ConsumerAwareRebalanceListener: Topic[{}] partitions[{}] RevokedBeforeCommit to consumer[{}]", new Object[]{topicName, partitions, consumer});
                }

            }
            @Override
            public void onPartitionsRevokedAfterCommit(Consumer<?, ?> consumer, Collection<TopicPartition> partitions) {
                if (ConsumerListenerContainerFactoryInitializer.log.isDebugEnabled()) {
                    ConsumerListenerContainerFactoryInitializer.log.debug("ConsumerAwareRebalanceListener: Topic[{}] partitions[{}] RevokedAfterCommit to consumer[{}]", new Object[]{topicName, partitions, consumer});
                }

            }
        });
    }

    private int resolveConcurrencyForSingleHostMode(String topicName) {
        String topicPartition = this.springEnvironment.getProperty("kafka.customization.partitions." + topicName);
        if (StringUtils.isEmpty(topicPartition)) {
            topicPartition = String.valueOf(1);
        }
        try {
            int i = Integer.parseInt(topicPartition);
            log.info("Resolved concurrency value [{}] for Message Listener Container for topic [{}] in single host mode", i, topicName);
            return i;
        } catch (NumberFormatException var4) {
            throw new IllegalArgumentException("Invalid partition config for topic: " + topicName + " in single host mode", var4);
        }
    }

    private AckMode resolveAckMode(String topicName) {
        AckMode ack = this.springEnvironment.getProperty(String.format("kafka.customization.listener-ack.%s", topicName), AckMode.class);
        return ack;
    }

    private int resolveConcurrency(String topicName) {
        if (this.isSingleHostMode) {
            return this.resolveConcurrencyForSingleHostMode(topicName);
        } else {
            String concurrencyStr = this.springEnvironment.getProperty(String.format("kafka.customization.concurrency.%s", topicName));

            try {
                int cc = Integer.parseInt(concurrencyStr);
                log.info("Found custom concurrency value [{}] for Message Listener Container for topic [{}]", cc, topicName);
                return cc;
            } catch (NumberFormatException var4) {
                log.info("No custom concurrency value found for Message Listener Container for topic [{}], using default value [{}]", topicName, 1);
                return 1;
            }
        }
    }
    private int resolveSessionTimeout(String topicName) {
        String sessionTimeoutStr = this.springEnvironment.getProperty(String.format("kafka.customization.session-timeout-ms.%s", topicName));

        try {
            int cc = Integer.parseInt(sessionTimeoutStr);
            log.info("Found custom session-timeout-ms value [{}] for Message Listener Container for topic [{}]", cc, topicName);
            return cc;
        } catch (NumberFormatException var4) {
            log.info("No custom session-timeout-ms value found for Message Listener Container for topic [{}], using default value [{}]", topicName, this.defaultSessionTimeoutMills);
            return this.defaultSessionTimeoutMills;
        }
    }

    private boolean resolveBatchListener(String topicName) {
        String batchListener = this.springEnvironment.getProperty(String.format("kafka.customization.batch-listener.%s", topicName));
        if (StringUtils.isNotBlank(batchListener)) {
            boolean batchListenerEnabled = Boolean.parseBoolean(batchListener);
            log.info("Found custom batch-listener value [{}] for Message Listener Container for topic [{}]", batchListener, topicName);
            return batchListenerEnabled;
        } else {
            log.info("No custom batch-listener value found for Message Listener Container for topic [{}], set it as [false]", topicName);
            return false;
        }
    }

    private int resolveMaxPollRecords(String topicName) {
        String maxPollRecStr = this.springEnvironment.getProperty(String.format("kafka.customization.max-poll-records.%s", topicName));

        try {
            int cc = Integer.parseInt(maxPollRecStr);
            log.info("Found custom max-poll-records value [{}] for Message Listener Container for topic [{}]", cc, topicName);
            return cc;
        } catch (NumberFormatException var4) {
            log.info("No custom max-poll-records value found for Message Listener Container for topic [{}], using default value [{}]", topicName, this.defaultMaxPollRecords);
            return this.defaultMaxPollRecords;
        }
    }

    private int resolveMaxPollIntervalMs(String topicName) {
        String maxPollIntervalMsStr = this.springEnvironment.getProperty(String.format("kafka.customization.max-poll-interval-ms.%s", topicName));

        try {
            int maxPollIntervalMs = Integer.parseInt(maxPollIntervalMsStr);
            log.info("Found custom max-poll-interval-ms value [{}] for Message Listener Container for topic [{}]", maxPollIntervalMs, topicName);
            return maxPollIntervalMs;
        } catch (NumberFormatException var4) {
            log.info("No custom max-poll-interval-ms value found for Message Listener Container for topic [{}], using default value [{}]", topicName, this.defaultMaxPollIntervalMills);
            return this.defaultMaxPollIntervalMills;
        }
    }

    protected ConsumerFactory<String, String> consumerFactory(TopicBeanProvider topicBeanProvider, String topicName) {
        Map<String, Object> props = new HashMap();
        props.put("bootstrap.servers", this.brokerHosts);
        props.put("group.id", topicBeanProvider.getConsumerGroupId());
        props.put("enable.auto.commit", this.enableAutoCommit);
        props.put("auto.commit.interval.ms", this.autoCommitIntervalMills);
        int sessionTimeout = this.resolveSessionTimeout(topicName);
        props.put("session.timeout.ms", sessionTimeout);
        if (sessionTimeout != this.defaultSessionTimeoutMills) {
            props.put("request.timeout.ms", sessionTimeout + 1);
            props.put("heartbeat.interval.ms", sessionTimeout / 3 - 1);
        }

        props.put("max.poll.records", this.resolveMaxPollRecords(topicName));
        props.put("max.poll.interval.ms", this.resolveMaxPollIntervalMs(topicName));
        props.put("key.deserializer", IntegerDeserializer.class);
        props.put("value.deserializer", this.getValueDeserializer(topicBeanProvider, topicName));
        return new DefaultKafkaConsumerFactory(props);
    }

    protected Class<?> getValueDeserializer(TopicBeanProvider topicBeanProvider, String topicName) {
        List<String> jsonTopicNames = topicBeanProvider.getJsonTopicNames();
        return jsonTopicNames != null && jsonTopicNames.contains(topicName) ? MsgSizeLoggedStringDeserializer.class : KryoObjDeserializer.class;
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
    }
}
