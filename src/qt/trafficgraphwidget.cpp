// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "trafficgraphwidget.h"
#include "clientmodel.h"
#include "guitheme.h"

#include <QPainter>
#include <QPainterPath>
#include <QColor>
#include <QTimer>

#include <cmath>

#define DESIRED_SAMPLES         800

#define XMARGIN                 10
#define YMARGIN                 10

TrafficGraphWidget::TrafficGraphWidget(QWidget *parent) :
    QWidget(parent),
    timer(0),
    fMax(0.0f),
    nMins(0),
    vSamplesIn(),
    vSamplesOut(),
    nLastBytesIn(0),
    nLastBytesOut(0),
    clientModel(0)
{
    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &TrafficGraphWidget::updateRates);
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, [this] { update(); });
}

void TrafficGraphWidget::setClientModel(ClientModel *model)
{
    clientModel = model;
    if(model) {
        nLastBytesIn = model->getTotalBytesRecv();
        nLastBytesOut = model->getTotalBytesSent();
    }
}

int TrafficGraphWidget::getGraphRangeMins() const
{
    return nMins;
}

void TrafficGraphWidget::paintPath(QPainterPath &path, QQueue<float> &samples)
{
    int h = height() - YMARGIN * 2, w = width() - XMARGIN * 2;
    int sampleCount = samples.size(), x = XMARGIN + w, y;
    if(sampleCount > 0) {
        path.moveTo(x, YMARGIN + h);
        for(int i = 0; i < sampleCount; ++i) {
            x = XMARGIN + w - w * i / DESIRED_SAMPLES;
            y = YMARGIN + h - (int)(h * samples.at(i) / fMax);
            path.lineTo(x, y);
        }
        path.lineTo(x, YMARGIN + h);
    }
}

void TrafficGraphWidget::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const GUIUtil::ThemeColors& colors = GUIUtil::themeColors();
    painter.fillRect(rect(), QColor(colors.panel));

    if(fMax <= 0.0f) return;

    const QColor axisCol(colors.inkFaint);
    int h = height() - YMARGIN * 2;
    painter.setPen(axisCol);
    painter.drawLine(XMARGIN, YMARGIN + h, width() - XMARGIN, YMARGIN + h);

    // decide what order of magnitude we are
    int base = floor(log10(fMax));
    float val = pow(10.0f, base);

    const QString units     = tr("KB/s");
    const float yMarginText = 2.0;

    // draw lines
    painter.setPen(axisCol);
    painter.drawText(XMARGIN, YMARGIN + h - h * val / fMax-yMarginText, QString("%1 %2").arg(val).arg(units));
    for(float y = val; y < fMax; y += val) {
        int yy = YMARGIN + h - h * y / fMax;
        painter.drawLine(XMARGIN, yy, width() - XMARGIN, yy);
    }
    // if we drew 3 or fewer lines, break them up at the next lower order of magnitude
    if(fMax / val <= 3.0f) {
        val = pow(10.0f, base - 1);
        painter.setPen(QColor(colors.border));
        painter.drawText(XMARGIN, YMARGIN + h - h * val / fMax-yMarginText, QString("%1 %2").arg(val).arg(units));
        int count = 1;
        for(float y = val; y < fMax; y += val, count++) {
            // don't overwrite lines drawn above
            if(count % 10 == 0)
                continue;
            int yy = YMARGIN + h - h * y / fMax;
            painter.drawLine(XMARGIN, yy, width() - XMARGIN, yy);
        }
    }

    if(!vSamplesIn.empty()) {
        QPainterPath p;
        paintPath(p, vSamplesIn);
        QColor fill(colors.teal);
        fill.setAlpha(70);
        painter.fillPath(p, fill);
        painter.setPen(QPen(QColor(colors.teal), 1.5));
        painter.drawPath(p);
    }
    if(!vSamplesOut.empty()) {
        QPainterPath p;
        paintPath(p, vSamplesOut);
        QColor fill(colors.wine);
        fill.setAlpha(70);
        painter.fillPath(p, fill);
        painter.setPen(QPen(QColor(colors.wine), 1.5));
        painter.drawPath(p);
    }
}

void TrafficGraphWidget::updateRates()
{
    if(!clientModel) return;

    quint64 bytesIn = clientModel->getTotalBytesRecv(),
            bytesOut = clientModel->getTotalBytesSent();
    float inRate = (bytesIn - nLastBytesIn) / 1024.0f * 1000 / timer->interval();
    float outRate = (bytesOut - nLastBytesOut) / 1024.0f * 1000 / timer->interval();
    vSamplesIn.push_front(inRate);
    vSamplesOut.push_front(outRate);
    nLastBytesIn = bytesIn;
    nLastBytesOut = bytesOut;

    while(vSamplesIn.size() > DESIRED_SAMPLES) {
        vSamplesIn.pop_back();
    }
    while(vSamplesOut.size() > DESIRED_SAMPLES) {
        vSamplesOut.pop_back();
    }

    float tmax = 0.0f;
    for (float f : vSamplesIn) {
        if(f > tmax) tmax = f;
    }
    for (float f : vSamplesOut) {
        if(f > tmax) tmax = f;
    }
    fMax = tmax;
    update();
}

void TrafficGraphWidget::setGraphRangeMins(int mins)
{
    nMins = mins;
    int msecsPerSample = nMins * 60 * 1000 / DESIRED_SAMPLES;
    timer->stop();
    timer->setInterval(msecsPerSample);

    clear();
}

void TrafficGraphWidget::clear()
{
    timer->stop();

    vSamplesOut.clear();
    vSamplesIn.clear();
    fMax = 0.0f;

    if(clientModel) {
        nLastBytesIn = clientModel->getTotalBytesRecv();
        nLastBytesOut = clientModel->getTotalBytesSent();
    }
    timer->start();
}
