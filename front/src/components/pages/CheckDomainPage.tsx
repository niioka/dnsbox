import {PageBase} from "@/components/pages/PageBase.tsx";
import {Input} from "@/components/ui/input.tsx";
import {useCallback, useState} from "react";
import {Button} from "@/components/ui/button.tsx";
import {NotFoundError} from "@/api/error.ts";
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from "@/components/ui/select.tsx";

type CheckDomainResponse = {
    domain: string
    ttl: number
    record: string
}

type State = {
    domain: string,
    response?: CheckDomainResponse
    resultText: string
}

const checkDomain = async ({ domain, resourceType }: { domain: string, resourceType: number }) => {
    const q = new URLSearchParams({ domain, resourceType: `${resourceType}` })
    const resp =  await fetch(`/api/check?${q}`)
    if (resp.status === 404) {
        throw new NotFoundError()
    }
    return await resp.json() as Promise<CheckDomainResponse>
}

export const CheckDomainPage = () => {
    const [state, setState] = useState<State>({
        domain: '',
        resultText: '',
    })

    const handleCheck = useCallback(async () => {
        try {
            const resp = await checkDomain({
                domain: state.domain,
                resourceType: 1,
            })
            setState({...state, resultText: resp.record})
        } catch (error: unknown) {
            if (error instanceof NotFoundError) {
                setState({...state, resultText: "レコードは存在しません"})
                return
            }
            setState({...state, resultText: "通信エラーが発生しました"})
        }
    }, [state])

    return (
        <PageBase>
            <div className="size-full flex justify-center items-center">
                <div className="w-[400px] flex flex-col gap-y-4">
                    <div className="grid grid-cols-1 gap-4 md:grid-cols-[1fr_100px]">
                        <div>
                            <div>Domain</div>
                            <Input value={state.domain} onChange={ev => setState({ ...state, domain: ev.target.value}) }/>
                        </div>
                        <div className="w-full">
                            <div>Type</div>
                            <Select>
                                <SelectTrigger className="w-full">
                                    <SelectValue  />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="A">A</SelectItem>
                                    <SelectItem value="TXT">TXT</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                    </div>

                    <div className="flex flex-row-reverse">
                        <Button onClick={handleCheck}>Check</Button>
                    </div>
                    {state.resultText &&
                        <div>{state.resultText}</div>
                    }
                </div>
            </div>
        </PageBase>
    )
}