pipeline {
    agent {
        docker { image 'zcoinofficial/zcoin-builder:latest' }
    }
    environment {
        CCACHE_DIR = '/tmp/.ccache'
    }
    stages {
        stage('Build') {
            steps {
                sh 'git clean -d -f -f -q -x'
                sh './autogen.sh'
                sh './configure'
                sh 'make dist'
                sh 'mkdir -p tmp'
                sh 'tar xf zcoin-*.tar.gz -C tmp'
                sh 'mv tmp/zcoin-* tmp/zcoin'
                dir('tmp/zcoin') {
                    sh './configure'
                    sh 'make -j6'
                }
            }
        }
        stage('Test') {
            steps {
                dir('tmp/zcoin') {
                    sh 'make check'
                }
            }
        }
    }
}
