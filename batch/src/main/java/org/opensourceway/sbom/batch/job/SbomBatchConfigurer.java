package org.opensourceway.sbom.batch.job;

import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.configuration.annotation.BatchConfigurer;
import org.springframework.batch.core.explore.JobExplorer;
import org.springframework.batch.core.explore.support.JobExplorerFactoryBean;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.core.launch.support.SimpleJobLauncher;
import org.springframework.batch.core.repository.JobRepository;
import org.springframework.batch.core.repository.dao.Jackson2ExecutionContextStringSerializer;
import org.springframework.batch.core.repository.support.JobRepositoryFactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.batch.BatchProperties;
import org.springframework.boot.autoconfigure.transaction.TransactionManagerCustomizers;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

/**
 * refactor by org.springframework.boot.autoconfigure.batch.JpaBatchConfigurer
 */
@Component
public class SbomBatchConfigurer implements BatchConfigurer, InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(SbomBatchConfigurer.class);

    private final BatchProperties properties;

    private final DataSource dataSource;

    private PlatformTransactionManager transactionManager;

    private final TransactionManagerCustomizers transactionManagerCustomizers;

    private final EntityManagerFactory entityManagerFactory;

    private JobRepository jobRepository;

    private JobLauncher jobLauncher;

    private JobExplorer jobExplorer;

    protected SbomBatchConfigurer(BatchProperties properties, DataSource dataSource, TransactionManagerCustomizers transactionManagerCustomizers, EntityManagerFactory entityManagerFactory) {
        this.properties = properties;
        this.dataSource = dataSource;
        this.transactionManagerCustomizers = transactionManagerCustomizers;
        this.entityManagerFactory = entityManagerFactory;
    }

    @Override
    public JobRepository getJobRepository() {
        return this.jobRepository;
    }

    @Override
    public PlatformTransactionManager getTransactionManager() {
        return this.transactionManager;
    }

    @Override
    public JobLauncher getJobLauncher() {
        return this.jobLauncher;
    }

    @Override
    public JobExplorer getJobExplorer() throws Exception {
        return this.jobExplorer;
    }

    @Override
    public void afterPropertiesSet() {
        initialize();
    }

    public void initialize() {
        try {
            this.transactionManager = buildTransactionManager();
            this.jobRepository = createJobRepository();
            this.jobLauncher = createJobLauncher();
            this.jobExplorer = createJobExplorer();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to initialize Spring Batch", ex);
        }
    }

    protected JobExplorer createJobExplorer() throws Exception {
        PropertyMapper map = PropertyMapper.get();
        JobExplorerFactoryBean factory = new JobExplorerFactoryBean();
        factory.setDataSource(this.dataSource);
        map.from(this.properties.getJdbc()::getTablePrefix).whenHasText().to(factory::setTablePrefix);
        // custom serializer
        factory.setSerializer(new Jackson2ExecutionContextStringSerializer(BatchContextConstants.JACKSON_SERIALIZER_TRUSTED_CLASS_NAME));
        factory.afterPropertiesSet();
        return factory.getObject();
    }

    protected JobLauncher createJobLauncher() throws Exception {
        SimpleJobLauncher jobLauncher = new SimpleJobLauncher();
        jobLauncher.setJobRepository(getJobRepository());
        jobLauncher.afterPropertiesSet();
        return jobLauncher;
    }

    protected JobRepository createJobRepository() throws Exception {
        JobRepositoryFactoryBean factory = new JobRepositoryFactoryBean();
        PropertyMapper map = PropertyMapper.get();
        map.from(this.dataSource).to(factory::setDataSource);
        map.from(this::determineIsolationLevel).whenNonNull().to(factory::setIsolationLevelForCreate);
        map.from(this.properties.getJdbc()::getTablePrefix).whenHasText().to(factory::setTablePrefix);
        map.from(this::getTransactionManager).to(factory::setTransactionManager);
        // custom serializer
        factory.setSerializer(new Jackson2ExecutionContextStringSerializer(BatchContextConstants.JACKSON_SERIALIZER_TRUSTED_CLASS_NAME));
        factory.afterPropertiesSet();
        return factory.getObject();
    }

    private PlatformTransactionManager buildTransactionManager() {
        PlatformTransactionManager transactionManager = createTransactionManager();
        if (this.transactionManagerCustomizers != null) {
            this.transactionManagerCustomizers.customize(transactionManager);
        }
        return transactionManager;
    }

    protected String determineIsolationLevel() {
        BatchProperties.Isolation isolation = this.properties.getJdbc().getIsolationLevelForCreate();

        if (isolation != null) {
            return toIsolationName(isolation);
        } else {
            logger.warn("JPA does not support custom isolation levels, so locks may not be taken when launching Jobs. "
                    + "To silence this warning, set 'spring.batch.jdbc.isolation-level-for-create' to 'default'.");
            return toIsolationName(BatchProperties.Isolation.DEFAULT);
        }
    }

    protected PlatformTransactionManager createTransactionManager() {
        return new JpaTransactionManager(this.entityManagerFactory);
    }

    private static final String PREFIX = "ISOLATION_";

    String toIsolationName(BatchProperties.Isolation isolation) {
        return PREFIX + isolation.name();
    }

}
