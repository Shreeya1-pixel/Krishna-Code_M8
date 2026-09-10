import React, { useEffect, useRef } from 'react'

interface LogLine {
  text: string
  type: 'info' | 'success' | 'error' | 'warn' | 'blocked' | 'system'
  timestamp?: string
}

interface Props {
  lines: LogLine[]
  maxHeight?: number
}

const TYPE_COLORS: Record<string, string> = {
  info: 'text-gray-500',
  success: 'text-green-600',
  error: 'text-red-600',
  warn: 'text-amber-600',
  blocked: 'text-[#005bb5]',
  system: 'text-[#005bb5]',
}

const TYPE_PREFIX: Record<string, string> = {
  info: '[INFO]',
  success: '[OK]  ',
  error: '[FAIL]',
  warn: '[PART]',
  blocked: '[BLOK]',
  system: '[SYS] ',
}

export default function TerminalLog({ lines, maxHeight = 400 }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  return (
    <div
      className="terminal rounded-lg p-4 overflow-y-auto"
      style={{ maxHeight, minHeight: 120 }}
    >
      {/* Terminal header */}
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-gray-200">
        <div className="w-3 h-3 rounded-full bg-red-500/80" />
        <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
        <div className="w-3 h-3 rounded-full bg-green-500/80" />
        <span className="ml-2 text-xs text-gray-500">M8 Assessment Console</span>
      </div>

      {lines.length === 0 ? (
        <div className="text-gray-400 text-sm">Waiting for assessment to start...</div>
      ) : (
        lines.map((line, i) => (
          <div key={i} className={`flex gap-2 text-xs leading-6 ${TYPE_COLORS[line.type]}`}>
            <span className="text-gray-400 select-none w-16 flex-shrink-0">
              {line.timestamp || '00:00:00'}
            </span>
            <span className="select-none opacity-60">{TYPE_PREFIX[line.type]}</span>
            <span className="flex-1 break-all">{line.text}</span>
          </div>
        ))
      )}
      <div ref={bottomRef} />
    </div>
  )
}
