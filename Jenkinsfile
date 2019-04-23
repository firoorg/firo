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
                sh 'mkdir -p dist'
                sh 'tar -C dist --strip-components=1 -xzf zcoin-*.tar.gz'
                dir('dist') {
                    sh './configure'
                    sh 'make -j6'
                }
            }
        }
        stage('Test') {
            steps {
                dir('dist') {
                    sh 'make check'
                }
            }
        }
        stage('RPC Tests') {
            steps {
                dir('dist') {
                    sh 'TIMEOUT=120 qa/pull-tester/run-bitcoind-for-test.sh qa/pull-tester/rpc-tests.py -extended'
                }
            }
        }
    }
}
