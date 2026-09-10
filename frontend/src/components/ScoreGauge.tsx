import React from 'react'
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts'

interface Props {
  value: number  // 0-1
  label: string
  size?: number
}

export default function ScoreGauge({ value, label, size = 140 }: Props) {
  const pct = Math.round(value * 100)
  const color = value > 0.6 ? '#ef4444' : value > 0.2 ? '#f97316' : '#22c55e'
  const data = [{ value: pct, fill: color }]

  return (
    <div className="flex flex-col items-center">
      <div style={{ width: size, height: size }} className="relative">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            cx="50%" cy="50%"
            innerRadius="60%" outerRadius="90%"
            startAngle={225} endAngle={-45}
            data={data}
          >
            <RadialBar
              background={{ fill: '#e5e7eb' }}
              dataKey="value"
              cornerRadius={8}
              max={100}
            />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold" style={{ color }}>{pct}%</span>
        </div>
      </div>
      <div className="text-xs text-gray-500 mt-1">{label}</div>
    </div>
  )
}
